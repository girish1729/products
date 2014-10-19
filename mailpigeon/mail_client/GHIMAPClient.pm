#!/usr/bin/perl

package GHIMAPClient;
use strict;
use warnings;

use Exporter;
use Mail::IMAPClient;
use DateTime;
use POSIX qw(strftime);
use Email::MIME;
use File::Path qw(make_path);
use DateTime;
use IO::Socket::SSL;
use DBI;
use Log::Log4perl qw(get_logger);
use File::Basename qw(dirname);

my (%mailinfo, $toid, $savepath) = ();
my ($msgdate, $sentdate, $senttime, $dbstr) = ();

use Cwd  qw(abs_path);
use lib dirname(dirname(dirname abs_path $0)) . '/mails/configs';

require "imapclient.conf";

my $logfile = $GHIMAPConfig::smuuthconfig{logfile};
my $logsize = $GHIMAPConfig::smuuthconfig{logsize};
my $lognumf = $GHIMAPConfig::smuuthconfig{lognumf};
my $dbtype = $GHIMAPConfig::smuuthconfig{dbtype}; 

my $instance_root = dirname(dirname(dirname abs_path $0));

sub getlogfilename {
	my $dt = DateTime->now; # same as ( epoch => time() )
        my $y = $dt->year;
        my $m = $dt->month;
	$m = sprintf "%02d", $m;

	my $logf = "$instance_root/log/$logfile-$y-$m.txt";
	return $logf;
}

# Configuration in a string ...
         my $conf = q(
           log4perl.category.Mail.IMAPClient = DEBUG, Logfile

           log4perl.appender.Logfile = Log::Log4perl::Appender::File
           log4perl.appender.Logfile.filename = sub { return &GHIMAPClient::getlogfilename; }
           log4perl.appender.Logfile.layout   = Log::Log4perl::Layout::PatternLayout
	   log4perl.PatternLayout.cspec.Z = sub { return strftime("%Z", localtime)}
	   log4perl.appender.Logfile.layout.ConversionPattern = %d %Z %c(%P) %p %m%n

         );

            # ... passed as a reference to init()
         Log::Log4perl::init( \$conf );
         my $log = Log::Log4perl::get_logger("Mail::IMAPClient");


sub dbconnect {
	my $dbname = $GHIMAPConfig::smuuthconfig{dbname};
	my $dbserver = $GHIMAPConfig::smuuthconfig{dbserver};
	my $dbserverport = $GHIMAPConfig::smuuthconfig{dbserverport};
	my $dbuser = $GHIMAPConfig::smuuthconfig{dbuser};
	my $dbpass = $GHIMAPConfig::smuuthconfig{dbpass};
	my $db = DBI->connect("dbi:$dbtype:dbname=$dbname;" .
		"host=$dbserver;port=$dbserverport", 
		 "$dbuser", "$dbpass", {AutoCommit => 0}); 

	if(!defined($db)) {
		$log->error("Could not connect to Postgres db");
	}
	$db->{RaiseError} = 1;
	return $db;
}

sub dbfinish {
	my ($db) = @_;
	# End transaction and commit changes to DB
	$db->commit or $log->error("Could not commit changed to DB"),die "Could not commit change to DB\n";
	$db->disconnect or $log->error("Could not disconnect from DB"),die"Could not disconnect from DB\n";
	$db = undef;
	$log->debug("DB Finish completed");
}

sub retnow { 
	my ($imap) = @_;
	$log->info("No messages: ", $imap->LastError);
	return undef;
}

sub talkimap {
	my ($serverip, $username, $userpass) = @_;

	my $imap = Mail::IMAPClient->new(
			Server   => $serverip,
			User     => $username,
			Password => $userpass,
			Ssl      => 0,
			Uid      => 1,
			);
	die "$0: connect: $@\n" if defined $@; 

	my $readmails = "Read";
	my $folder = "INBOX";
	#my $readmails = "INBOX";
	#my $folder = "Read";

	$imap->select( $folder)
		or die "Select $folder error: ", $imap->LastError, "\n";
	$log->debug( "$folder folder selected\n");

	my @msgs = $imap->messages or return &retnow($imap);
	my $nummsg = $#msgs + 1;
	$log->info( "Found $nummsg messages in $folder \n");

	(%mailinfo, $toid) = ();
	my $db = dbconnect();
	my $idx = 1;
	$log->debug( "Connected to DB");
	for my $msgnum (@msgs) {
		my %tmph = ();
		$tmph{msgnum} = $msgnum;
		my $h = $imap->parse_headers($msgnum,
			"Subject", "Date", "From", "To",  "Message-ID")  
			or die "parse_headers failed" , $imap->LastError, "\n";
		for my $hdr (keys %$h) {
			my $v = $h->{$hdr}[0];	 
			my $out ="$hdr:$v";
			if($out =~ /To/) {
				$toid = $h->{$hdr}[0];
				$toid =~ /(\S+@\S+)/;
				$toid = $1;
				$toid =~ s/[<>"]//g;
			}
			$tmph{$hdr} = $v;
		}
		$log->debug( "Parsed headers of mail $msgnum");

		my $dt = DateTime->now->set_time_zone('Asia/Kolkata');
		my $isodate = $dt->iso8601();

		$isodate =~ /(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)/;
		my $y = $1;
		my $m = $2;
		my $d = $3;
		my $H = $4;
		my $M = $5;
		my $S = $6;

		my $padidx = sprintf("%03d", $idx);
		my $yearmon = "$y-$m";
		my $fileprefix = "$y$m${d}_${H}${M}${S}_$padidx";

		$savepath= "$instance_root/mails/clients/$yearmon/$toid/incoming";
		make_path($savepath);
		$log->debug( "Created save path $savepath");
		my $s = $imap->size($msgnum)  ;
		$tmph{Size} =  $s;

		my $bodyfilename = "${fileprefix}-mail_body.txt";
		$tmph{bodyfilename} = $bodyfilename;
		$tmph{bodyfilepath} = $savepath;

		my $fullmsg = "$savepath/${fileprefix}-mbox_mail.txt";
		$imap->message_to_file($fullmsg, $msgnum) or
	          $log->error("Could not write FULL msg to" 
		   . "$savepath/${fileprefix}-mbox_mail.txt"),
			die "Could not save full mail";
		$log->debug( "Wrote FULL msg to $savepath/${fileprefix}-mbox_mail.txt");

		my $attcnt = 0;
		my (@attach, %fnames) = ();
		my $msgstr = $imap->message_string($msgnum)
			or $log->error("$0: Can't get msg string: $@");

		open BODY, ">$savepath/$bodyfilename";
		$log->debug("$0: About to walk parts(MIME parsing) now");
		Email::MIME->new($msgstr)->walk_parts(sub {
			my ($part) = @_;
			my $name = undef;
			$name = $part->filename;

			if(defined($part->content_type)) {
				if (($part->content_type =~ /text\/plain/) or 
				  ($part->content_type =~ /text\/html/)) {
					print BODY $part->body() . "\n";
					$log->debug("$0: Written  "
					. "body of msgid $msgnum");
					$log->debug( "Wrote msg body to $savepath/${fileprefix}-mail_body.txt");
				}
			}

			if(defined($name)) {
				# Replace all special chars in file name
				$name =~ s/[\s`~!@#\$\%\^\*\(\)\+=\[\]\{\}\\\|<>\/\?'",;:]/_/g;

				$attcnt++;
				my $ftype = $part->content_type;
				$log->debug("Got MIME part name as $name");
				return unless($name =~ /\.pdf$/i);
				$log->debug( "$0: Writing attachment ${fileprefix}-$name...\n");
				open my $fh, ">$savepath/${fileprefix}-$name"
				or $log->error("Error writing" .
				  "$savepath/${fileprefix}-$name"),die "$0: ERROR writing " .
				  "$savepath/${fileprefix}-$name: $!";
				print $fh $part->content_type =~ m!^text/!
				? $part->body_str : $part->body
				or die "$0: print $name: $!";
				close $fh or warn "$0: close $name: $!";
				$log->debug( "$0: Wrote attachment ${fileprefix}-$name...\n");
				$fnames{name} = $savepath . "/${fileprefix}-$name";
				push @attach, "${fileprefix}-$name";
			}
		});
		close(BODY);

		$tmph{attcnt} = 0;
		$tmph{numvalid} = 0;
		if($attcnt > 0) {
			$tmph{attcnt} =  $attcnt;
			$tmph{filelist} =  [@attach];
			my $n = 0;
			for my $t (@attach) {
				if($t =~ /\.pdf/i) {
					$n++;
				}
			}
			$tmph{numvalid} = $n;
		}
		$mailinfo{$msgnum} = {%tmph};
		$imap->move($readmails, $msgnum)
			or WARN( "Could not move message: $msgnum\n");
		$log->debug("Moved msg $msgnum");
		$idx++;
	}

	$imap->close() or WARN("Could not close IMAP: $imap->LastError");
# Logout from IMAP server
	$imap->logout or ERR("Logout error: ", $imap->LastError, "\n");
	$log->debug("IMAP server closed");
	return ($db,%mailinfo);
}

sub munchdate {

	$msgdate =~ s/^\s+(.*)\s+$/$1/g;

	my @vals = split(/ /, $msgdate);
	my $datestr = join "-", @vals[1..3];
	$senttime = $vals[4]; 
	my $mon = ();


	my ($d, $m, $y) = split /-/, $datestr;

	if($m =~ /Jan/) {
		$mon = "01";
	} elsif($m =~ /Feb/){
		$mon = "02";
	} elsif($m =~ /Mar/){
		$mon = "03";
	} elsif($m =~ /Apr/){
		$mon = "04";
	} elsif($m =~ /May/){
		$mon = "05";
	} elsif($m =~ /Jun/){
		$mon = "06";
	} elsif($m =~ /Jul/){
		$mon = "07";
	} elsif($m =~ /Aug/){
		$mon = "08";
	} elsif($m =~ /Sep/){
		$mon = "09";
	} elsif($m =~ /Oct/){
		$mon = "10";
	} elsif($m =~ /Nov/){
		$mon = "11";
	} elsif($m =~ /Dec/){
		$mon = "12";
	}
	$d = sprintf "%02d", $d;
	$sentdate = "$y-$mon-$d";
}

sub insmailattachdb {
# XXX insert all values into the DB
	my ($db, %mailinfo) = @_;
	for my $mail (sort keys %mailinfo) {
		if($dbtype =~ /Pg/) {
			$dbstr = "insert into RECEIVED_VIRPHY_EMAILS values(DEFAULT,";
		} else {
			$dbstr = "insert into RECEIVED_VIRPHY_EMAILS values(0,";
		}

		my ($msgid, $fromemail, $fromid,$fromname, $tomail, $toname, 
				$recvdate, $recvtime, $sub, $numatt, $numvalid, 
				$bodyfilename, $bodyfilepath,
				$processtatus, $liminput, $sendcnt, $pcem_id) = ();

		my (@attachlist, $toid, $toemail, $date, $size, $rvpe_id) = ();

		my %t = %{$mailinfo{$mail}};

		$msgid = $t{'Message-ID'};
		$size = $t{Size};

		$fromid = $t{From};
		$fromid =~ /(\S+@\S+)/;
		$fromemail = $1;
		$fromemail =~ s/[<>"]//g;
		if($fromid =~ /\(/) {
			$fromid =~ /\((.*)\)/;
			$fromname = $1;
		} else {
			$fromid =~ /^(.*?)\S+@\S+(.*)$/;
			$fromname = $1 . $2;
		}
		unless($fromname =~ /\w/) {
			$fromid =~ /(\S+)@/;
			$fromname = $1;
		}
		$fromname =~  s/[<>"]//g;

		$toid = $t{To};
		$toid =~ /(\S+@\S+)/;
		$toemail = $1;
		$toemail =~ s/[<>"]//g;
		$toid =~ /^(.*?)\S+@\S+(.*)$/;
		$toname = $1 . $2;
		unless($toname =~ /\w/) {
			$toid =~ /(\S+)@/;
			$toname = $1;
		}
		$toname =~  s/[<>"]//g;
                                                 
		my $stmt = $db->prepare(
		"SELECT VPEM_FIRST_NAME,VPEM_MIDDLE_NAME,VPEM_LAST_NAME " . 
		"FROM VIRPHY_EMAIL_IDS WHERE VPEM_EMAIL = '$toemail';"); 

		$stmt->execute() or die "Could not execute SQL statement\n";
  		my @row = $stmt->fetchrow_array;
		for my $id (0..2) {
			$row[$id] = ' ' unless(defined($row[$id]));
		}
		$toname = join " ", @row;
		$toname =~ s/\s+/ /g;

	 	$msgdate = $t{Date};

		&munchdate;

		my $dt = DateTime->now->set_time_zone('Asia/Kolkata');
		my $isodate = $dt->iso8601();

		$isodate =~ /(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)/;
		my $y = $1;
		my $m = $2;
		my $d = $3;
		my $H = $4;
		my $M = $5;
		my $S = $6;

		$recvdate = "$y-$m-$d";
		$recvtime = "$H:$M:$S";

		$sub = $t{Subject};
		$sub = substr $sub, 0, 194;
		$numatt = $t{attcnt};
		@attachlist = @{$t{filelist}};
		$numvalid = $t{numvalid};
		$bodyfilename = $t{bodyfilename};
		$bodyfilepath = $t{bodyfilepath};
		$processtatus = "PENDING"; 
		$liminput = ""; 
		$sendcnt = 0; 
		$pcem_id = 0; 

		$dbstr .= "'$msgid', '$fromemail',"
			. "'$fromname', '$toemail', '$toname',"
			. " '$sentdate', '$senttime', '$recvdate', '$recvtime',"
			. "'$sub', '$bodyfilename', '$bodyfilepath', $numatt, $numvalid,"
			. "'$processtatus', '$liminput', $sendcnt, $pcem_id);";

		$log->debug( "About to insert [ $dbstr ] ");
		eval {
			my $stmt = $db->prepare($dbstr) or $log->error("Error in DB insertion");
			$stmt->execute() or 
			   $log->error("Could not insert into RECEIVED_VIRPHY_EMAILS");
		};
		$db->rollback if($@);
		$log->info( "DONE inserting into RECEIVED_VIRPHY_EMAILS");
		# Now get the rvpe_id from the above insert
		my $queryrvpeid = "select max(RVPE_ID) from RECEIVED_VIRPHY_EMAILS;";
		my $q = $db->prepare($queryrvpeid) or $log->error("Error in DB query\n");
		$q->execute() or $log->error("Could not query RVPE_ID");
		($rvpe_id) = $q->fetchrow_array();

# Now add all attachments for the mail in question
		for my $att (@attachlist) {
			my $rvat_attach_path = $savepath;
			my $rvat_attach_name = $att;
			my $rvat_attach_valid = 0;
			my $rvat_rvpe_id = $rvpe_id;
			$rvat_attach_valid = 1 if($rvat_attach_name =~ /\.pdf$/i);
			if($dbtype =~ /Pg/) {
				$dbstr = "insert into RECEIVED_ATTACHMENTS values(DEFAULT,";
			} else {
				$dbstr = "insert into RECEIVED_ATTACHMENTS values(0,";
			}

			$dbstr .= "$rvat_rvpe_id, '$rvat_attach_name',"
				. "'$rvat_attach_path', $rvat_attach_valid);";

			$log->debug("About to insert into " .
					"RECEIVED_ATTACHMENTS [ $dbstr ] ");
			eval {
				$stmt = $db->prepare($dbstr) or $log->error("Error in DB
						insertion\n");
				$stmt->execute() or $log->error("Could not insert: $!\n");
			};
			$db->rollback if($@);
			$log->info( "DONE inserting into RECEIVED_ATTACHMENTS");
		}
		system("$instance_root/exec/scripts/add_items_to_queue.sh" .
		   " rulesQueue $rvpe_id");
		$log->info( "add_items_to_queue of $rvpe_id executed ");
	}
	GHIMAPClient::dbfinish($db);
	return 0;
}


my @EXPORT = qw(fixattachtable getlogfilename insmaildb talkimap dbconnect dbfinish);
1;
