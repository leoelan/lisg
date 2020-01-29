#!/usr/bin/perl -w

use strict;

use FindBin '$Bin';
use lib $Bin . "/../lib";

use POSIX;
use Fcntl;
use Sys::Syslog;
use Getopt::Long;

use ISG;

my $cfg_source;

GetOptions("conf=s" => \$cfg_source);

if (!defined($cfg_source)) {
	$cfg_source = $Bin . "/../etc/config.pl";
}

require $cfg_source;
our %cfg;

my $data;
my $sk;
my %rad_reqs;
my $rad_packet_id = 0;
my $last_watch = 0;
my %child = ();
my %jobs = ();
my $dying = 0;
my $nas_ip;
my $nas_id;

$SIG{INT}  = \&term_all;
$SIG{KILL} = \&term_all;
$SIG{TERM} = \&term_all;

$SIG{CHLD} = sub {
	while ((my $pid = waitpid(-1, WNOHANG)) > 0) {
		if ($pid > -1 && (my $job = delete($child{$pid}))) {
			my $rc = $? >> 8;
			my $str_info = "Job '$job' (PID $pid) was finished.";
			if ($rc == 254) {
				do_log("err", "$str_info Main process (PID $$) exiting too.");
				kill('TERM', $$);
			} elsif (!$dying) {
				do_log("err", "$str_info Trying to restart.");
				make_new_child($jobs{$job}, 0, $job);
			}
		}
	}
};

sub term_all {
	my $sig = shift;
	$dying = 1;

	do_log("info", "Got signal $sig. Terminating all childs and finishing.");
	unlink($cfg{pid_file});

	my $count = kill('TERM' => keys %child);
	exit(0);
}

$nas_ip = ISG::isg_get_nas_ip();

if (!length($nas_ip)) {
	do_log("warning", "Unable to get my own IP-address, using 127.0.0.1");
	$nas_ip = "127.0.0.1";
}

if (defined($cfg{nas_identifier})) {
	$nas_id = $cfg{nas_identifier};
} else {
	$nas_id = $nas_ip;
}

my $s_sel = IO::Select->new();

my $rad_dict = ISG::load_radius_dictionary($cfg{radius_dictionary});

&check_pid();

my $ev; my %rep;

foreach my $srv_name (keys %{$cfg{srv}}) {
	prepare_service($srv_name);
}

my %tc_names; &reload_tc(0, 0, \%tc_names);

$sk = prepare_netlink_socket();
if ($sk < 0) {
	do_log("fatal", "Unable to open netlink socket: $!");
	exit(254);
}

if (isg_send_event($sk, { 'type' => ISG::EVENT_SDESC_SWEEP_TC }, \%rep) < 0) {
	do_log("fatal", "Unable to sweep service descriptions ($!)");
	exit(254);
}

foreach my $tc_name (keys %tc_names) {
	foreach my $srv_name (keys %{$cfg{srv}}) { 
		if (grep {$tc_name eq $_} @{$cfg{srv}{$srv_name}{traffic_classes}}) {

			$ev->{'type'} = ISG::EVENT_SDESC_ADD;
			$ev->{'nehash_tc_name'} = $tc_name;
			$ev->{'service_name'} = $srv_name;

			if (isg_send_event($sk, $ev, \%rep) < 0) {
				do_log("err", "Unable to add service description ($!)");
			}
		}
	}
}

close($sk);
undef(%tc_names);

&daemonize() if ($cfg{daemonize});

$jobs{"ISG"}        = \&job_isg;
$jobs{"CoA"}        = \&job_coa;
$jobs{"TC_Refresh"} = \&job_reload_tc;

foreach my $job (keys %jobs) {
	make_new_child($jobs{$job}, 0, $job);
}

while (1) {
	sleep(1);
}

############################################################

sub job_isg {
	$sk = prepare_netlink_socket();
	if ($sk < 0) {
		do_log("err", "Unable to open netlink socket: $!");
		exit(254);
	}

	my $netlink_sk = $sk;
	fcntl($sk, F_SETFL, O_NONBLOCK);

	$s_sel->add($sk);

	my $ev;

	$ev->{'type'} = ISG::EVENT_LISTENER_REG;

	if (isg_send_event($sk, $ev) < 0) {
		do_log("err", "Unable to register in kernel: $!");
		exit(254);
	}

	do_log("info", "ISG job initialization done for NAS '$nas_ip', entering main loop");

	while (1) {
		if (my @read_sks = $s_sel->can_read(1)) {
		foreach my $rsk (@read_sks) {
			my $err = 0;
			if (!sysread($rsk, $data, 1500)) {
				$err++;
			}

			if ($rsk == $netlink_sk) {
				if ($err) {
					do_log("err", "Error reading NETLINK event ($!)");
					next;
				}

				my $ev = isg_parse_event($data);

				if ($ev->{'type'} == ISG::EVENT_SESS_CREATE) {
					send_radius_request("Access-Request", $ev);
				} elsif ($ev->{'type'} == ISG::EVENT_SESS_START ||
						$ev->{'type'} == ISG::EVENT_SESS_UPDATE ||
						$ev->{'type'} == ISG::EVENT_SESS_STOP) {

					my $ipaddr = ISG::long2ip($ev->{'ipaddr'});
					my $nat_ipaddr = ISG::long2ip($ev->{'nat_ipaddr'});

					unless ($ev->{'flags'} & ISG::NO_ACCT) {
						send_radius_request("Accounting-Request", $ev);
					}

					if ($ev->{'flags'} & ISG::IS_SERVICE && $ev->{'type'} == ISG::EVENT_SESS_START) {
						do_log("info", "Service '" . $ev->{'service_name'} . "' for '$ipaddr' started");
					} elsif ($ev->{'type'} == ISG::EVENT_SESS_STOP) {

						if ($ev->{'flags'} & ISG::IS_APPROVED_SESSION) {
							make_new_child($cfg{cb_on_session_stop}, { "ipaddr" => $ipaddr, "nat_ipaddr" => $nat_ipaddr }) if defined($cfg{cb_on_session_stop});
							do_log("info", "Session '$ipaddr' on 'Virtual" . $ev->{'port_number'} . "' finished");
						} elsif ($ev->{'flags'} & ISG::IS_SERVICE) {
							do_log("info", "Service '" . $ev->{'service_name'} . "' for '$ipaddr' finished");
						}
					}
				}
			} else {
				my $src_host = $rsk->peerhost();
				my $src_port = $rsk->peerport();

				my $wait_key = $rsk->peerhost() . "-" . $rsk->sockport();

				if (!defined($rad_reqs{"$wait_key"})) {
					do_log("err", "Unexpected reply from '$src_host:$src_port', dropping packet");
					goto out;
				}

				my $exp_id    = $rad_reqs{"$wait_key"}{'pk_rid'};
				my $exp_ev    = $rad_reqs{"$wait_key"}{'pk_ev'};
				my $exp_login = ISG::long2ip($exp_ev->{'ipaddr'});

				if ($err) {
					do_log("err", "Error receiving RADIUS reply for '$exp_login' from '$src_host:$src_port' ($!)");
					goto out;
				}

				my $rp = decode_radius_packet($data);

				if (!defined($rp) || (defined($rp) && ref($rp) ne "Net::Radius::Packet")) {
					do_log("err", "Unable to parse RADIUS reply for '$exp_login' from '$src_host:$src_port'");
					$err++;
					goto out;
				}

				if ($exp_id != $rp->identifier()) {
					do_log("err", "Unexpected RADIUS reply identifier for '$exp_login' from '$src_host:$src_port'");
					$err++;
					goto out;
				}

				if ($rp->code eq "Access-Accept" || ($rp->code eq "Access-Reject" && defined($cfg{unauth_service_name_list}))) {
					my $oev;
					my @rate_info;

					my %srv_list;
					if ($rp->vsattributes($rad_dict->vendor_num("Cisco"))) {
						my $cisco_ai = $rp->vsattr($rad_dict->vendor_num("Cisco"), "Cisco-Account-Info");
						if (defined($cisco_ai)) {
							foreach my $val (@{$cisco_ai}) {
								if ($val =~ /^(A|N)(.+)/) {
									$srv_list{$2} = $1;
								} elsif ($val =~ /^QC;(.+?);/) {
									my $ev;
									my $srv_name = "DYN_" . uc(substr(Digest::MD5::md5_hex($val), 0, 16));
									my $class = $1;

									$cfg{srv}{$srv_name}{rate_info} = $val;
									$cfg{srv}{$srv_name}{traffic_classes} = [ $class ];

									prepare_service($srv_name);

									$srv_list{$srv_name} = "A";

									$ev->{'type'} = ISG::EVENT_SDESC_ADD;
									$ev->{'nehash_tc_name'} = $class;
									$ev->{'service_name'} = $srv_name;
									$ev->{'service_flags'} = ISG::SERVICE_DESC_IS_DYNAMIC;

									if (isg_send_event($sk, $ev) < 0) {
										do_log("err", "Unable to add dynamic service description ($!)");
									}

								} elsif ($val =~ /^Q/) {
									@rate_info = parse_account_qos($val);
								} else {
									do_log("err", "Unknown attribute Cisco-Account-Info = $val, ignoring");
								}
							}
						}
					} elsif ($rp->code eq "Access-Reject") {
						foreach my $srv_name (@{$cfg{unauth_service_name_list}}) {
							if ($srv_name =~ /^(A|N)(.+)/) {
								$srv_list{$2} = $1;
							}
						}
					}

					%srv_list = sanitize_services_list(\%srv_list);

					my $nat_ipaddr     = $rp->attr('Framed-IP-Address');
					my $alive_interval = $rp->attr('Acct-Interim-Interval');
					my $max_duration   = $rp->attr('Session-Timeout');
					my $idle_timeout   = $rp->attr('Idle-Timeout');
					my $class          = $rp->attr('Class');

					$oev->{'type'} = ISG::EVENT_SESS_APPROVE;
					$oev->{'port_number'} = $exp_ev->{'port_number'};

					$oev->{'alive_interval'} = defined($alive_interval) ? $alive_interval : $cfg{session_alive_interval};
					$oev->{'idle_timeout'} = defined($idle_timeout) ? $idle_timeout : $cfg{session_idle_timeout};

					$oev->{'cookie'} = substr($class, 0, 32) if (defined($class));

					if ($rp->code eq "Access-Reject" && defined($cfg{unauth_session_max_duration})) {
						$oev->{'max_duration'} = $cfg{unauth_session_max_duration};
					} else {
						$oev->{'max_duration'} = defined($max_duration) ? $max_duration : $cfg{session_max_duration};
					}

					if (scalar(@rate_info) == 4) {
						$oev->{'in_rate'}  = $rate_info[0];
						$oev->{'in_burst'} = $rate_info[1];
			
						$oev->{'out_rate'}  = $rate_info[2];
						$oev->{'out_burst'} = $rate_info[3];
					}

					foreach my $srv_name (keys %srv_list) {
						my $sev = prepare_service_event($srv_name);

						$sev->{'type'} = ISG::EVENT_SERV_APPLY;
						$sev->{'port_number'} = $exp_ev->{'port_number'};
						$sev->{'flags'} |= $srv_list{$srv_name} eq "A" ? ISG::SERVICE_STATUS_ON : 0;

						if (isg_send_event($sk, $sev) < 0) {
							do_log("err", "Error sending EVENT_SERV_APPLY for service '$srv_name': $!");
						}
					}

					if (defined($nat_ipaddr)) {
						$oev->{'nat_ipaddr'} = ISG::ip2long($nat_ipaddr);
					} else {
						$nat_ipaddr = "0.0.0.0";
					}

					if (defined($cfg{no_accounting}) || $rp->code eq "Access-Reject") {
						$oev->{'flags'} |= ISG::NO_ACCT;
					}

					if (isg_send_event($sk, $oev) < 0) {
						do_log("err", "Error sending EVENT_SESS_APPROVE: $!");
					}

					make_new_child($cfg{cb_on_session_start}, { "ipaddr" => $exp_login, "nat_ipaddr" => $nat_ipaddr }) if defined($cfg{cb_on_session_start});
					do_log("info", "Session '$exp_login' on 'Virtual" . $exp_ev->{'port_number'} ."' accepted by '$src_host:$src_port'");

				} elsif ($rp->code eq "Access-Reject") {
					my $oev;

					do_log("info", "Session '$exp_login' rejected by '$src_host:$src_port'");

					$oev->{'type'} = ISG::EVENT_SESS_CHANGE;
					$oev->{'port_number'} = $exp_ev->{'port_number'};
					$oev->{'max_duration'} = defined($cfg{unauth_session_max_duration}) ? $cfg{unauth_session_max_duration} : 60;

					if (isg_send_event($sk, $oev) < 0) {
						do_log("err", "Error sending reply for SESS_CHANGE: $!");
					}

					} elsif ($rp->code eq "Accounting-Response") {
						## No-Op.

					} else {
						do_log("err", "Unexpected RADIUS reply code (" . $rp->code . ") for '$exp_login'");
					}
out:
					my $pk_ev    = $rad_reqs{"$wait_key"}{'pk_ev'};
					my $conf_key = $rad_reqs{"$wait_key"}{'pk_ckey'};
					my $prio     = $rad_reqs{"$wait_key"}{'pk_prio'};

					destroy_radius_socket($rsk, $wait_key);

					if ($err) {
						send_radius_request($conf_key, $pk_ev, $prio + 1);
					}
				}
			}
		}

		# Watch for RADIUS requests waiting for server reply
		if ($s_sel->count > 1 && $last_watch != time()) {
			my $now = time();
			my @all_sks = $s_sel->handles;

			foreach my $rsk (@all_sks) {
				if ($rsk != $netlink_sk) {
					my $wait_key = $rsk->peerhost() . "-" . $rsk->sockport();

					my $pk_ev    = $rad_reqs{"$wait_key"}{'pk_ev'};
					my $conf_key = $rad_reqs{"$wait_key"}{'pk_ckey'};
					my $prio     = $rad_reqs{"$wait_key"}{'pk_prio'};

					if ($now - $rad_reqs{"$wait_key"}{'pk_time'} > $cfg{$conf_key}{$prio}{timeout}) {
						my $src_host = $rsk->peerhost();
						my $src_port = $rsk->peerport();

						do_log("err", "Timeout waiting RADIUS reply for '" . ISG::long2ip($pk_ev->{'ipaddr'}) . "' from '$src_host:$src_port'");
						destroy_radius_socket($rsk, $wait_key);

						send_radius_request($conf_key, $pk_ev, $prio + 1);
					}
				}
			}
			$last_watch = time();
		}
	}
}

sub job_coa {
	my $sock = IO::Socket::INET->new(
		Proto     => 'udp',
		LocalPort => $cfg{coa_port},
	);

	if (!$sock) {
		do_log("err", "Unable to create CoA socket ($!)");
		exit(254);
	}

	my $sockk = prepare_netlink_socket();

	if ($sockk < 0) {
		do_log("err", "Unable to open netlink socket for CoA ($!)");
		exit(254);
	}

	while ($sock->recv($data, 1500)) {
		my $nas_ident; my $nas_ipaddr;
		my $out_code; my $out_err; my $ack_code; my $nak_code;
		my $ev; my %ev_in;

		my $ipaddr = Socket::inet_ntoa((Socket::sockaddr_in($sock->peername))[1]);

		if (defined($cfg{coa_server}) && $ipaddr ne $cfg{coa_server}) {
			do_log("err", "Only " . $cfg{coa_server} . " is allowed to send CoA requests, ignore packet from '$ipaddr'");
			next;
		}

		if (!Net::Radius::Packet::auth_acct_verify($data, $cfg{coa_secret})) {
			do_log("err", "Host $ipaddr send incorrect authenticator (check coa_secret), ignore packet");
			next;
		}

		my $rp = decode_radius_packet($data);

		if (!defined($rp) || (defined($rp) && ref($rp) ne "Net::Radius::Packet")) {
			do_log("err", "Unable to parse CoA request from '$ipaddr'");
			next;
		}

		if ($rp->code eq "Disconnect-Request") {
			$ack_code = "Disconnect-ACK";
			$nak_code = "Disconnect-NAK";
		} elsif ($rp->code eq "CoA-Request") {
			$ack_code = "CoA-ACK";
			$nak_code = "CoA-NAK";
		} else {
			do_log("err", "Host $ipaddr send incorrect RADIUS code, ignore packet");
			next;
		}

		$out_code = $nak_code;

		$nas_ident  = $rp->attr("NAS-Identifier");
		$nas_ipaddr = $rp->attr("NAS-IP-Address");

		if ((!defined($nas_ident) && !defined($nas_ipaddr)) ||
			(defined($nas_ident) && $nas_id ne $nas_ident) ||
			(defined($nas_ipaddr) && $nas_ip ne $nas_ipaddr)) {
			$out_err = "NAS-Identification-Mismatch";

			do_log("err", "NAS identification error, can't process CoA request");
			goto send_rp;
		}

		my $session_id = $rp->attr("Acct-Session-Id");
		my $nas_port   = $rp->attr("NAS-Port");
		my $username   = $rp->attr("User-Name");

		if (defined($username) && !($username =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
			undef($username);
		}

		if ($session_id) {
			$ev->{'session_id'} = ISG::hex_session_id_to_llu($session_id);
		} elsif ($nas_port) {
			$ev->{'port_number'} = $nas_port;
		} elsif ($username) {
			$ev->{'ipaddr'} = ISG::ip2long($username);
		} else {
			$out_err = "Missing-Attribute";

			do_log("err", "Can't process request: CoA need User-Name, Acct-Session-Id, or NAS-Port attribute");
			goto send_rp;
		}

		if ($rp->code eq "Disconnect-Request") {
			$ev->{'type'} = ISG::EVENT_SESS_CLEAR;
		} else {
			my @rate_info;
			if ($rp->vsattributes($rad_dict->vendor_num("Cisco"))) {
				my $cisco_ai = $rp->vsattr($rad_dict->vendor_num("Cisco"), "Cisco-Account-Info");
				if (defined($cisco_ai)) {
					foreach my $val (@{$cisco_ai}) {
						if ($val =~ /^Q/) {
							@rate_info = parse_account_qos($val);
						}
					}
				}
		
				my $cisco_ap = $rp->vsattr($rad_dict->vendor_num("Cisco"), "Cisco-AVPair");
				if (defined($cisco_ap)) {
					my $slist;
					my %pars;
		
					foreach my $val (@{$cisco_ap}) {
						next if ($val !~ /^subscriber:(.*)=(.*)/);
						$pars{$1} = $2;
					}

					if (!defined($pars{"command"})) {
						$out_err = "Missing-Attribute";
						goto send_rp;
					}

					if ($pars{"command"} =~ /(a|dea)ctivate-service/) {
						my $session_id;

						if (!defined($pars{"service-name"})) {
							$out_err = "Missing-Attribute";
							goto send_rp;
						}

						$ev->{'type'} = ISG::EVENT_SERV_GETLIST;
		
						if (($slist = isg_get_list($sockk, $ev)) < 0) {
							do_log("err", "Unable to get sessions/services list: $!");
							next;
						}
		
						my %srv_list;
						foreach my $cev (@{$slist}) {
							$srv_list{$cev->{'service_name'}} = $cev->{'flags'} & ISG::SERVICE_STATUS_ON ? "A" : "N";
							if ($pars{"service-name"} eq $cev->{'service_name'}) {
								$session_id = ISG::hex_session_id_to_llu($cev->{'session_id'});
							}
						}

						if (!defined($session_id)) {
							do_log("err", "Unable to find '" . $pars{"service-name"} . "' service");
							$out_err = "Session-Context-Not-Found";
							goto send_rp;
						}

						my $flags = ISG::IS_SERVICE | ISG::SERVICE_STATUS_ON;
						my $flags_op = 0;

						if ($pars{"command"} eq "activate-service") {
							$srv_list{$pars{"service-name"}} = "A";
							$flags_op = ISG::FLAG_OP_SET;
						} else {
							$srv_list{$pars{"service-name"}} = "N";
							$flags_op = ISG::FLAG_OP_UNSET;
						}
			
						%srv_list = sanitize_services_list(\%srv_list);

						if ($flags_op == ISG::FLAG_OP_SET && $srv_list{$pars{"service-name"}} eq "N") {
							goto send_rp;
						}

						$ev = prepare_service_event($pars{"service-name"});

						$ev->{'session_id'} = $session_id;
						$ev->{'flags'} = $flags;
						$ev->{'flags_op'} = $flags_op;

					} else {
						do_log("err", "Unknown command '" . $pars{"command"} . "'");
						$out_err = "Unsupported-Attribute";
						goto send_rp;
					}
				}
			}

			if (scalar(@rate_info) == 4) {
				$ev->{'in_rate'}  = $rate_info[0];
				$ev->{'in_burst'} = $rate_info[1];

				$ev->{'out_rate'}  = $rate_info[2];
				$ev->{'out_burst'} = $rate_info[3];
			}

			$ev->{'type'} = ISG::EVENT_SESS_CHANGE;
		}

		if (isg_send_event($sockk, $ev, \%ev_in) < 0) {
			do_log("err", "Unable to disconnect or change session parameters: $!");
			next;
		}
	
		if ($ev_in{'type'} != ISG::EVENT_KERNEL_ACK) {
			$out_err  = "Session-Context-Not-Found";
		} else {
			$out_code = $ack_code;
		}

send_rp:
		my $p = new Net::Radius::Packet $rad_dict;

		$p->set_code($out_code);
		$p->set_identifier($rp->identifier);
		$p->set_authenticator($rp->authenticator);

		if (defined($out_err) && length($out_err)) {
			$p->set_attr("Error-Cause", $out_err);
		}

		$p->set_authenticator(Digest::MD5::md5($p->pack . $cfg{coa_secret}));

		if (!$sock->send($p->pack)) {
			do_log("err", "Unable to send CoA reply");
		}
	}
}

sub job_reload_tc {
	my $prev_md5 = reload_tc(1);

	while (1) {
		my $ret = reload_tc(0, $prev_md5);

		if ($ret) {
			$prev_md5 = $ret;
		}
		sleep($cfg{tc_check_interval});
	}
}

############################################################

sub sanitize_services_list {
	my $srv_list = shift;

	my %on_cls_list; my %ret;

	foreach my $srv_name (keys %{$srv_list}) {
		my $srv_status = $srv_list->{$srv_name};
		my $srv_type = $cfg{srv}{$srv_name}{type};

		if (!$cfg{srv}{$srv_name}) {
			do_log("warning", "Service '$srv_name' is not defined in configuration, ignoring");
			next;
		}

		$ret{$srv_name} = "N";

		if ($srv_status eq "A") {
			my $overlap = 0;
			my $class_list = $cfg{srv}{$srv_name}{traffic_classes};
			foreach my $cclass (@{$class_list}) {
				if ($on_cls_list{$srv_type}{$cclass}) {
					do_log("warning", "Service '$srv_name' has overlapping class with also active service '$on_cls_list{$srv_type}{$cclass}', ignoring auto-start on both");
					$overlap = 1;
					$ret{$on_cls_list{$srv_type}{$cclass}} = $ret{$srv_name} = "N";
					last;
				}
			}

			if (!$overlap) {
				$ret{$srv_name} = "A";
				$on_cls_list{$srv_type}{$_} = $srv_name foreach (@{$class_list});
			}
		}
	}

	return %ret;
}

sub prepare_service {
	my $srv_name = shift;

	if (!defined($cfg{srv}{$srv_name}{traffic_classes})) {
		do_log("err", "At least one class must be defined, throw service '$srv_name'");
		delete($cfg{srv}{$srv_name});
		return;
	}

	if (defined($cfg{srv}{$srv_name}{rate_info})) {
		my @rate_info = parse_account_qos($cfg{srv}{$srv_name}{rate_info});
		if (scalar(@rate_info) == 4) {
			$cfg{srv}{$srv_name}{u_rate}  = $rate_info[0];
			$cfg{srv}{$srv_name}{u_burst} = $rate_info[1];
			$cfg{srv}{$srv_name}{d_rate}  = $rate_info[2];
			$cfg{srv}{$srv_name}{d_burst} = $rate_info[3];
		} else {
			do_log("err", "Bad service rate specification, throw service '$srv_name'");
			delete($cfg{srv}{$srv_name});
			return;
		}
	} else {
		$cfg{srv}{$srv_name}{u_rate}  = 0;
		$cfg{srv}{$srv_name}{u_burst} = 0;
		$cfg{srv}{$srv_name}{d_rate}  = 0;
		$cfg{srv}{$srv_name}{d_burst} = 0;
	}

	$cfg{srv}{$srv_name}{alive_interval} = $cfg{session_alive_interval} if (!defined($cfg{srv}{$srv_name}{alive_interval}));
	$cfg{srv}{$srv_name}{max_duration} = $cfg{session_max_duration} if (!defined($cfg{srv}{$srv_name}{max_duration}));
	$cfg{srv}{$srv_name}{idle_timeout} = $cfg{session_idle_timeout} if (!defined($cfg{srv}{$srv_name}{idle_timeout}));
	$cfg{srv}{$srv_name}{type} = "policer" if (!defined($cfg{srv}{$srv_name}{type}));
}

sub prepare_service_event {
	my ($srv_name, $sev) = @_;

	$sev->{'service_name'} = $srv_name;

	$sev->{'out_rate'} = $cfg{srv}{$srv_name}{d_rate};
	$sev->{'out_burst'} = $cfg{srv}{$srv_name}{d_burst};

	$sev->{'in_rate'} = $cfg{srv}{$srv_name}{u_rate};
	$sev->{'in_burst'} = $cfg{srv}{$srv_name}{u_burst};

	$sev->{'alive_interval'} = $cfg{srv}{$srv_name}{alive_interval};
	$sev->{'idle_timeout'} = $cfg{srv}{$srv_name}{idle_timeout};
	$sev->{'max_duration'} = $cfg{srv}{$srv_name}{max_duration};

	$sev->{'flags'} = 0;

	if (defined($cfg{srv}{$srv_name}{no_accounting})) {
		$sev->{'flags'} |= ISG::NO_ACCT;
	}

	if ($cfg{srv}{$srv_name}{type} eq "tagger") {
		$sev->{'flags'} |= ISG::SERVICE_TAGGER | ISG::NO_ACCT;
	}

	return $sev;
}

sub parse_account_qos {
	my $val = shift;
	my @ret;

	if ($val =~ /U;(\d{1,});(\d{1,})/) {
		push(@ret, $1);
		push(@ret, $2 * 8);
	}

	if ($val =~ /D;(\d{1,});(\d{1,})/) {
		push(@ret, $1);
		push(@ret, $2 * 8);
	}

	return @ret;
}

sub get_hi_32 {
	my $int = shift;
	return $int - (2**32 * int($int / 2**32));
}

sub do_log {
	if (!$cfg{daemonize} || $_[0] eq "fatal") {
		shift;
		printf(shift(@_) . "\n", @_);
	} else {
		openlog("ISG", "pid", $cfg{log_facility});
		syslog(@_);
		closelog();
	}
}

sub decode_radius_packet {
	my $data = shift;
	my $p = new Net::Radius::Packet $rad_dict, $data;

	return $p;
}

sub send_radius_request_server {
	my ($code, $ev, $conf_key, $prio) = @_;
	my $exp_code;

	my $sock = IO::Socket::INET->new(
		Proto    => "udp",
		PeerAddr => $cfg{$conf_key}{$prio}{server},
		Blocking => 0
	);

	if (!$sock) {
		do_log("err", "Unable to create RADIUS socket to '" . $cfg{$conf_key}{$prio}{server} . "' ($!)");
		return 0;
	}

	my $wait_key = $sock->peerhost() . "-" . $sock->sockport();

	$s_sel->add($sock);

	my $p = new Net::Radius::Packet $rad_dict;
	my $rid = $rad_packet_id++ % 256;

	my $username = ISG::long2ip($ev->{'ipaddr'});

	$p->set_code($code);

	$p->set_identifier($rid);

	if ($code eq "Accounting-Request") {
		$p->set_authenticator("\x0" x 16); ## Will recalculate it later
	} else {
		$p->set_authenticator(pack "C*", map { int rand 255 } 0..15);
		$p->set_password($username, $cfg{$conf_key}{$prio}{secret});
	}

	$p->set_attr("User-Name", $username);
	$p->set_attr("Calling-Station-Id", $username);

	$p->set_attr("Service-Type", "Framed-User");

	$p->set_attr("NAS-IP-Address", $nas_ip);

	$p->set_attr("NAS-Identifier", $nas_id);
	$p->set_attr("Called-Station-Id", $nas_id);

	$p->set_attr("NAS-Port", $ev->{'port_number'});
	$p->set_attr("NAS-Port-Type", "Virtual");

	if (defined($ev->{'macaddr'})) {
		$p->set_vsattr("Cisco", "Cisco-AVPair", "client-mac-address=" . ISG::format_mac($ev->{'macaddr'}, 4));
	}

	if ($code eq "Accounting-Request") {
		$p->set_attr("Acct-Status-Type", "Start") if ($ev->{'type'} == ISG::EVENT_SESS_START);
		$p->set_attr("Acct-Status-Type", "Alive") if ($ev->{'type'} == ISG::EVENT_SESS_UPDATE);
		$p->set_attr("Acct-Status-Type", "Stop") if ($ev->{'type'} == ISG::EVENT_SESS_STOP);

		if ($ev->{'nat_ipaddr'}) {
			$p->set_attr("Framed-IP-Address", ISG::long2ip($ev->{'nat_ipaddr'}));
		}

		$p->set_attr("Acct-Authentic", "RADIUS");
		$p->set_attr("Acct-Session-Id", $ev->{'session_id'});
		$p->set_attr("Acct-Session-Time", $ev->{'duration'});

		$p->set_attr("Acct-Input-Packets", $ev->{'in_packets'});
		$p->set_attr("Acct-Output-Packets", $ev->{'out_packets'});

		$p->set_attr("Acct-Input-String", get_hi_32($ev->{'in_bytes'}));
		$p->set_attr("Acct-Output-String", get_hi_32($ev->{'out_bytes'}));

		$p->set_attr("Acct-Input-Gigawords", int($ev->{'in_bytes'} / 2**32));
		$p->set_attr("Acct-Output-Gigawords", int($ev->{'out_bytes'} / 2**32));

		if (defined($ev->{'cookie'})) {
			$p->set_attr("Class", $ev->{'cookie'});
		}

		$p->set_vsattr("Cisco", "Cisco-Control-Info", "I" . int($ev->{'in_bytes'} / 2**32) . ";" . get_hi_32($ev->{'in_bytes'}));
		$p->set_vsattr("Cisco", "Cisco-Control-Info", "O" . int($ev->{'out_bytes'} / 2**32) . ";" . get_hi_32($ev->{'out_bytes'}));

		if (defined($ev->{'parent_session_id'})) {
			$p->set_vsattr("Cisco", "Cisco-AVPair", "parent-session-id=" . $ev->{'parent_session_id'});
		}

		if (defined($ev->{'service_name'})) {
			$p->set_vsattr("Cisco", "Cisco-Service-Info", "N" . $ev->{'service_name'});
		}
	}

	if ($code eq "Accounting-Request") {
		$p->set_authenticator(Digest::MD5::md5($p->pack . $cfg{$conf_key}{$prio}{secret}));
	}

	if (!$sock->send($p->pack)) {
		do_log("err", "Unable to send RADIUS request to '" . $cfg{$conf_key}{$prio}{server} . "' ($!)");
		destroy_radius_socket($sock, $wait_key);
		return 0;
	}

	$rad_reqs{"$wait_key"}{'pk_ev'}   = $ev;
	$rad_reqs{"$wait_key"}{'pk_rid'}  = $rid;
	$rad_reqs{"$wait_key"}{'pk_time'} = time();

	$rad_reqs{"$wait_key"}{'pk_ckey'} = $conf_key;
	$rad_reqs{"$wait_key"}{'pk_prio'} = $prio;

	return 1;
}

sub send_radius_request {
	my ($code, $ev, $from_prio) = @_;

	my $conf_key;

	if ($code eq "Access-Request") {
		$conf_key = "radius_auth";
	} elsif ($code eq "Accounting-Request") {
		$conf_key = "radius_acct";
	} elsif ($code eq "radius_auth") {
		$conf_key = "radius_auth";
		$code = "Access-Request";
	} elsif ($code eq "radius_acct") {
		$conf_key = "radius_acct";
		$code = "Accounting-Request";
	}

	if (defined($from_prio) && !defined($cfg{$conf_key}{$from_prio})) {
		goto out;
	}

	foreach my $prio (sort keys %{$cfg{$conf_key}}) {
		if (!defined($from_prio) || $prio >= $from_prio) {
			if (send_radius_request_server($code, $ev, $conf_key, $prio)) {
				return 1;
			}
		}
	}

out:
	my $username = ISG::long2ip($ev->{'ipaddr'});
	do_log("err", "No more servers to retry for '$username', give up");
	return 0;
}

sub destroy_radius_socket {
	my ($sk, $wait_key) = @_;

	$s_sel->remove($sk);
	close($sk);
	delete($rad_reqs{"$wait_key"});
}

sub reload_tc {
	my ($init_md5, $prev_md5, $tc_names) = @_;

	my $sk = prepare_netlink_socket();
	if ($sk < 0) {
		do_log("err", "Unable to open netlink socket for job_reload_tc ($!)");
		exit(254);
	}

	if (! -f $cfg{tc_file}) {
		return;
	}

	if (!open(FP, "<" . $cfg{tc_file})) {
		do_log("err", "Unable to open $cfg{tc_file} ($!)");
		exit(254);
	}

	my $md5 = Digest::MD5->new;
	$md5->addfile(*FP);
	my $curr_md5 = $md5->digest;

	if ($init_md5) {
		return $curr_md5;
	}

	if (!defined($prev_md5) || $curr_md5 ne $prev_md5) {
		my %pfx_list;

		my $err_str = "";
		my %rep;

		do_log("info", "Refreshing traffic classification table");

		seek(FP, 0, 0);
		while (<FP>) {
			chomp; s/^\s+//;
			if (/^([^#]\S*)\s+(.+)\/([0-9]{1,2})/) {
				my $mask = ($3 ? ~((1<<32 - $3)-1) : 0);
				my $prefix = $2 . "/" . ISG::long2ip($mask);

				if ($3 > 32 || ISG::ip2long($2) & ~$mask) {
					$err_str = "bad prefix: '$2/$3'";
				} elsif ($pfx_list{$prefix}) {
					$err_str = "duplicate prefix: $prefix";
				} else {
					$pfx_list{$prefix} = $1;
					$tc_names->{$1}++;
				}
			} elsif (length($_) && !(/^#/)) {
				$err_str = "bad line format: '$_'";
			}
			if (length($err_str)) {
				do_log("err", "Error in $cfg{tc_file}, " . $err_str);
				return;
			}
		}

		if (isg_send_event($sk, { 'type' => ISG::EVENT_NE_SWEEP_QUEUE }, \%rep) < 0) {
			do_log("fatal", "Unable to sweep ne queue ($!)");
			exit(254);
		}

		foreach my $key (keys %pfx_list) {
			my $ev;
			my ($net, $mask) = split(/\//, $key);

			$ev->{'type'} = ISG::EVENT_NE_ADD_QUEUE;
			$ev->{'nehash_pfx'} = ISG::ip2long($net);
			$ev->{'nehash_mask'} = ISG::ip2long($mask);
			$ev->{'nehash_tc_name'} = $pfx_list{$key};

			if (isg_send_event($sk, $ev, \%rep) < 0) {
				do_log("err", "Unable to add prefix to queue ($!)");
			}
		}

		if (isg_send_event($sk, { 'type' => ISG::EVENT_NE_COMMIT }, \%rep) < 0) {
			do_log("err", "Unable to commit queue ($!)");
			return;
		}

		do_log("info", scalar(keys %pfx_list) . " prefixes loaded to TC table");
	}

	close(FP);
	close($sk);

	return $curr_md5;
}

sub check_pid {
	my $pid = 0;

	if (-e $cfg{pid_file}) {
		open(PID, $cfg{pid_file});
		$pid = <PID>;
		close(PID);
	}

	if ($pid && -e "/proc/$pid/stat") {
		do_log("fatal", "My process is already exists (PID $pid), exit");
		exit(254);
	}
}

sub daemonize {
	my $pid;

	if ($pid = fork) { exit 0; }

	POSIX::setsid();
	$SIG{HUP} = 'IGNORE';
	if ($pid = fork) { exit 0; }
	chdir "/";
	umask 0;

	open(PIDFILE, ">$cfg{pid_file}");
	print(PIDFILE POSIX::getpid());
	close(PIDFILE);

	close(STDIN); close(STDOUT); close(STDERR);

	if ($cfg{debug}) {
		open(STDIN, "+>/tmp/ISGd_dbg.log");
	} else {
		open(STDIN, "+>/dev/null");
	}

	open(STDOUT, "+>&STDIN");
	open(STDERR, "+>&STDIN");
}

sub make_new_child {
	my ($job, $par, $job_name) = @_;

	my $pid;
	my $sigset;

	# block signal for fork
	$sigset = POSIX::SigSet->new(SIGINT);
	sigprocmask(SIG_BLOCK, $sigset) or die "Can't block SIGINT for fork: $!\n";

	if (!defined($pid = fork())) {
		do_log("err", "Unable to make new child: $!");
		return 0;
	}

	if ($pid) {
		sigprocmask(SIG_UNBLOCK, $sigset) or die "Can't unblock SIGINT for fork: $!\n";
		$child{$pid} = $job_name if (defined($job_name));
		return $pid;
	}

	$SIG{INT}  = 'DEFAULT';
	$SIG{KILL} = 'DEFAULT';
	$SIG{TERM} = 'DEFAULT';

	# unblock signals
	sigprocmask(SIG_UNBLOCK, $sigset) or die "Can't unblock SIGINT for fork: $!\n";

	$job->(defined($par) ? $par : 0);
	exit;
}
