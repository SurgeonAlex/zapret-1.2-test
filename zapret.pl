#!/usr/bin/perl -w
# При отсутствии к бд проверяем $DBH->state 1 подсоединено
use strict;
use warnings;
use File::Basename 'dirname';
use File::Spec;
use lib join '/',File::Spec->splitdir(dirname(__FILE__));
use Zapret;
use SOAP::Lite;
use DBI;
use Data::Dumper;
use MIME::Base64;
use utf8;
use XML::Simple qw(:strict);
use URI 1.69;
use NetAddr::IP;
use Digest::MD5 qw(md5_hex);
use Encode qw(decode_utf8 encode_utf8);
use Net::SMTP;
use POSIX;
use POSIX qw(strftime);
use Config::Simple;
use File::Basename;
use Net::IP qw(:PROC);
use AnyEvent;
use AnyEvent::DNS;
use Log::Log4perl;
use Getopt::Long;
use URI::UTF8::Punycode;
use File::Path qw(make_path);
use File::Copy;
use File::Pid;

my $abort_validate_rkn_dump = '/usr/local/etc/zapret/dump_xml_sig_is_not_valid.txt';
my $abort_validate_rkn_dump_delta = '/usr/local/etc/zapret/dump_delta_xml_sig_is_not_valid.txt';

if ( -e $abort_validate_rkn_dump || -e $abort_validate_rkn_dump_delta){
print "RKN SIGN NOT VALIDATE!!! Show work dir!!!\n";
exit 1;
}

my $lockFile = '/var/lock/subsys/zapretd.lock';
my $pidd = '/var/run/zapretd.pid';
if ( -e $lockFile && -e $pidd)
{
print "Program is Started, am exit 1 now";
exit 1;
}


$XML::Simple::PREFERRED_PARSER = 'XML::Parser';

binmode(STDOUT,':utf8');
binmode(STDERR,':utf8');


######## Config #########

my $unzip="/usr/bin/unzip";

my $dir = File::Basename::dirname($0);
my $Config = {};

my $config_file=$dir.'/zapret.conf';
my $force_load='';
my $log_file=$dir."/zapret_log.conf";

GetOptions("force_load" => \$force_load,
	    "log=s" => \$log_file,
	    "config=s" => \$config_file) or die "Error no command line arguments\n";

Config::Simple->import_from($config_file, $Config) or die "Can't open ".$config_file." for reading!\n";

Log::Log4perl::init( $log_file );

my $logger=Log::Log4perl->get_logger();

my $daemonName = "zapretd";
my $dieNow = 0;
my $pidFile     = '/var/run/'.$daemonName.".pid";
unlink $pidFile;
chdir '$dir';
umask 0;
open STDIN,  '<', '/dev/null' or die "Can't read /dev/null: $!";
open STDOUT, '>', '/dev/null' or die "Can't write to /dev/null: $!";
open STDERR, '>>', '/var/log/zapret-info-STDERR.log' or die "Can't write to /dev/null: $!";
defined(my $pid = fork) or die "Can't fork: $!";
exit 0 if $pid;
exit 1 if not defined $pid;
POSIX::setsid() or die "Can't start a new session.";
local $SIG{INT} = \&signalHandler;
local $SIG{TERM} = \&signalHandler; 
local $SIG{HUP} = \&signalHandler; 
local $SIG{KILL} = \&signalHandler; 
local $SIG{PIPE} = 'ignore';

my $pidfile = File::Pid->new({file => $pidFile,});
$pidfile->write or die "Can't write PID file, /dev/null: $!";

sub signalHandler
{
#    $dieNow = 1;
    $SIG{HUP}  = sub { $logger->info("Caught SIGHUP:  exiting gracefully"); $dieNow = 1; };
    $SIG{INT}  = sub { $logger->info("Caught SIGINT:  exiting gracefully"); $dieNow = 1; };
    $SIG{QUIT} = sub { $logger->info("Caught SIGQUIT:  exiting gracefully"); $dieNow = 1; };
    $SIG{TERM} = sub { $logger->info("Caught SIGTERM:  exiting gracefully"); $dieNow = 1; };
    $SIG{KILL} = sub { $logger->info("Caught SIGKILL:  exiting gracefully"); $dieNow = 1; };
}


$logger->info("\n\n");

my $api_url = $Config->{'API.url'} || die "API.url not defined.";
my $archive_path = $Config->{'PATH.archive'} || "";

my $db_host = $Config->{'DB.host'} || die "DB.host not defined.";
my $db_user = $Config->{'DB.user'} || die "DB.user not defined.";
my $db_pass = $Config->{'DB.password'} || die "DB.password not defined.";
my $db_name = $Config->{'DB.name'} || die "DB.name not defined.";

my $soap = new Zapret($api_url);

my $resolve = $Config->{'NS.resolve'} || 0;

my @resolvers = $Config->{'NS.resolvers'} || ();


my @resolvers_new;

foreach my $n (@{$resolvers[0]})
{
	push(@resolvers_new,AnyEvent::Socket::parse_address($n));
}

my $ipv6_nslookup = $Config->{'NS.ipv6_support'} || 0;
if(lc($ipv6_nslookup) eq "true" || lc($ipv6_nslookup) eq "yes")
{
	$ipv6_nslookup=1;
} else {
	$ipv6_nslookup=0;
}

my $keep_resolved = $Config->{'NS.keep_resolved'} || 0;
if(lc($keep_resolved) eq "yes" || lc($keep_resolved) eq "true")
{
	$keep_resolved=1;
} else {
	$keep_resolved=0;
}

my $dns_timeout = $Config->{'NS.timeout'} || 1;
$dns_timeout = int($dns_timeout) if($dns_timeout);

my $form_request = $Config->{'API.form_request'} || 0;

my $our_blacklist = $Config->{'PATH.our_blacklist'} || "";

my $openssl_bin_path="/usr/local/gostopenssl/bin/openssl";
my $rkn_sha1_fingerprint = $Config->{'API.rkn_fingerprint'} || 0;
chomp($rkn_sha1_fingerprint);

######## End config #####

my $DBH;
my ($lastDumpDateOld, $lastAction, $lastCode, $lastResult, $actualDate, $deltaId, $getDumpDeltaList, $isEmpty);
dbConnect();
getParams();

my %NEW = ();
my %OLD = ();
my %getOld = ();
my %OLD_ONLY_IPS = ();
my %OLD_DOMAINS = ();
my %OLD_URLS = ();
my %OLD_SUBNETS = ();
my %OLD_TRUE = ();
my %OLD_TRUE_ONLY_IPS = ();
my %OLD_TRUE_DOMAINS = ();
my %OLD_TRUE_URLS = ();
my %OLD_TRUE_SUBNETS = ();
my %EX_IPS = ();
my %EX_DOMAINS = ();
my %EX_SUBNETS = ();

my %ZAP_OLD_IPS;
my %ZAP_OLD_TRUE_IPS;

my %resolver_cache;

my $resolved_domains_ipv4=0;
my $resolved_domains_ipv6=0;
my $deleted_old_records=0;
my $added_ipv4_ips=0;
my $added_ipv6_ips=0;
my $added_domains=0;
my $added_urls=0;
my $added_subnets=0;
my $added_records=0;

$logger->debug("Last dump date:\t".$lastDumpDateOld);
$logger->debug("Last action:\t".$lastAction);
$logger->debug("Last code:\t".$lastCode);
$logger->debug("Last result:\t".$lastResult);

#############################################################
$logger->info("Starting zapret program at: ".localtime());
until($dieNow)
{
my $start_time=localtime();
$logger->info("Start vigruzka at ".$start_time);

if( $lastResult eq 'send' || $lastResult eq 'new' || $lastResult eq 'getDumpDeltaList_getResult' || $lastResult eq 'req-1')
{
	$logger->info("Last request is send, waiting for the data...");
	while (getResult())
	{
		$logger->info("Reestr not yet ready. Waiting...");
		sleep(10);
	}
	$logger->info("Stopping RKN at ".(localtime()));
#	exit 0;
}

elsif( $lastResult eq 'got' || $lastResult eq 'req_0' || $lastResult eq 'req_1')
{
	$logger->info("Last request is getDumpDeltaList, waiting for the data...");
	while (getDumpDeltaList())
	{
		$logger->info("Reestr not yet ready. Waiting...");
		sleep(10);
	}
	$logger->info("Stopping RKN at ".(localtime()));
#	exit 0;
}
$logger->info("Stopping vigruzka at ".(localtime()));

do{ $logger->info("Graceful exit! $pid"); exit } if $dieNow;
}#end until

$logger->info("Stopping Processing: $pidfile at:" .time());
exit 0;

sub getResult
{
	$logger->debug("Getting result...");

	my @result;
	eval
	{
		@result = $soap->getResult( $lastCode );
	};

	if( $@ )
	{
		$logger->fatal("Error while getResult(): ".$@);
		sleep(60);
		getResult();
	}

	if( !@result )
	{
		$logger->fatal("Result not defined!");
		$logger->error( Dumper( @result ));
		exit;
	}

	if( !($result[0] eq 'true' ) )
	{
		# Some error
		my $comment = $result[1];
		$logger->debug("Can not get result: ".$comment);
		# This is utf-8:
		if( $result[2] == 0 )
		{
			return 1;
		} else {
			set('lastResult', 'err');
			set('lastAction', 'getResult');
			sleep(60);
			getResult();
#			exit;
		}
	} else {
		unlink $dir.'/dump.xml';
		unlink $dir.'/dump.xml.sig';
		my $zip = decode_base64($result[1]);

		my $file = "arch.zip";
		my $tm=time();
		if($archive_path)
		{
			$file = strftime "Full-arch-%Y-%m-%d-%H_%M_%S.zip", localtime($tm);
		}

		open F, '>'.$dir."/".$file || warn "Can't open $dir/$file for writing!\n".$! ;
		binmode F;
		print F $zip;
		close F;
		`unzip -o $dir/$file -d $dir/`;
		if($archive_path)
		{
			my $apath = strftime "$archive_path/%Y/%Y-%m/%Y-%m-%d", localtime($tm);
			make_path($apath);
			copy($dir."/".$file,$apath."/".$file);
			unlink $dir."/".$file;
		}
		
		if ($rkn_sha1_fingerprint ne 0) {
		
		my $sig_fingerprint = `$openssl_bin_path pkcs7 -in $dir/dump.xml.sig -print_certs -inform DER > /tmp/rkn-dump.pem && $openssl_bin_path x509 -in /tmp/rkn-dump.pem -fingerprint -noout`;
		chomp($sig_fingerprint);
		
		if ( $rkn_sha1_fingerprint eq $sig_fingerprint ) {
		    $logger->info("SHA1 Fingerprint dump.xml.sig is valid");
			my $validation_content = `$openssl_bin_path smime -verify -in $dir/dump.xml.sig -noverify -inform der -content $dir/dump.xml 2>&1 >&3 3>&- | /bin/grep successful 3>&-`;
			    if ($validation_content =~ /Verification successful/) {
			    $logger->info("RKN dump.xml Verification successful");
			    unlink '/tmp/rkn-dump.pem';
			    } else {
			    $logger->info("RKN dump.xml and dump.xml.sig. Signer is not valid! Verification failed!!!");
			    exit 1;
			    }
		} else {
		$logger->info("RKN SHA1 Fingerprint dump.xml.sig $sig_fingerprint is not valid!!!");
		open my $fh, '>', $dir.'/dump_xml_sig_is_not_valid.txt';
		print {$fh} "RKN dump.xml.sig is NOT valid fingerprint $sig_fingerprint\n\n";
		print {$fh} "zapret.conf RKN Filgerprint is $rkn_sha1_fingerprint\n";
		print {$fh} $file. "\n";
		close $fh;
		exit 1;
		       }
                }
                
                
		$logger->info("\n\n");
		$logger->info("Got result getResult, parsing dump.");

		parseDump();

		set('lasltAction', 'getResult');
		set('lastResult', 'got');
		set('lastDumpDate', $actualDate);
		set('getDumpDeltaList', 0); #сотояние для зонда, сигнал что можно резолвить ip адреса

		# статистика
		$logger->info("Added: domains: ".$added_domains.", urls: ".$added_urls.", IPv4 ips: ".$added_ipv4_ips.", IPv6 ips: ".$added_ipv6_ips.", subnets: ".$added_subnets.", records: ".$added_records);
		$logger->info("Deleted: old records: ".$deleted_old_records);
		getParams();
		getDumpDeltaList();
		
	}
	return 0;
}

sub getDumpDelta
{
	$logger->debug("Getting result...DeltaId: $deltaId");

	my @result;
	eval
	{       
		my @params =  (SOAP::Data->name( 'deltaId' )->type("long")->value($deltaId));
                @result = $soap->getDumpDelta(@params);
#                $logger->debug(print Dumper(@result));
	};

	if( $@ )
	{
		$logger->fatal("Error while getDumpDelta(): ".$@); # http request error codes here
		sleep(60);
                getDumpDelta($deltaId);
		
	}

	if( !@result )
	{
		$logger->fatal("Result not defined! getDumpDelta");
		$logger->error( Dumper( @result ));
		sleep(60);
                getDumpDelta($deltaId);
	}

	if( ($result[0] eq "true" ) )
	{
		# Some error
		my $comment = $result[1];
		$logger->info("Can not get result: ".$comment);
		# This is utf-8:
		if( $result[2] == 0 )
		{
			return 1;
		} else {
			set('lastResult', 'err');
			set('lastAction', 'getResult');
			sleep(60);
			getDumpDelta($deltaId);
		}
	} else {
		unlink $dir.'/dump_delta.xml';
		unlink $dir.'/dump_delta.xml.sig';
		my $zip = decode_base64($result[1]);

		my $file = "arch_delta.zip";
		my $tm=time();
		if($archive_path)
		{
			$file = strftime "$deltaId-delta-arch_delta-%Y-%m-%d-%H_%M_%S.zip", localtime($tm);
		}

		open F, '>'.$dir."/".$file || warn "Can't open $dir/$file for writing!\n".$! ;
		binmode F;
		print F $zip;
		close F;
		`unzip -o $dir/$file -d $dir/`;
		if($archive_path)
		{
			my $apath = strftime "$archive_path/%Y/%Y-%m/%Y-%m-%d", localtime($tm);
			make_path($apath);
			copy($dir."/".$file,$apath."/".$file);
			unlink $dir."/".$file;
		}
		
		if($rkn_sha1_fingerprint ne 0) {
		
		my $sig_fingerprint = `$openssl_bin_path pkcs7 -in $dir/dump_delta.xml.sig -print_certs -inform DER > /tmp/rkn-dump_delta.pem && $openssl_bin_path x509 -in /tmp/rkn-dump_delta.pem -fingerprint -noout`;
		chomp($sig_fingerprint);
		
		if ( "$rkn_sha1_fingerprint" eq "$sig_fingerprint" ) {
			$logger->info("SHA1 Fingerprint dump_delta.xml.sig is valid");
			my $validation_content_delta = `$openssl_bin_path smime -verify -in $dir/dump_delta.xml.sig -noverify -inform der -content $dir/dump_delta.xml 2>&1 >&3 3>&- | /bin/grep successful 3>&-`;
			    
			    if ($validation_content_delta =~ /Verification successful/) {
			    $logger->info("RKN dump_delta.xml is Verification successful");
			    unlink '/tmp/rkn-dump_delta.pem';
			    } else {
			    $logger->info("RKN dump_delta.xml and dump_delta.xml.sig. Signer is not valid! Verification failed!!!");
			    exit 1;
			    }
		} else {
		$logger->info("RKN SHA1 Fingerprint dump_delta.xml.sig $sig_fingerprint is not valid!!!");
		open my $fh, '>', $dir.'/dump_delta_xml_sig_is_not_valid.txt';
		print {$fh} "RKN dump_delta.xml.sig deltaId: $deltaId is NOT valid fingerprint $sig_fingerprint\n";
		print {$fh} "zapret.conf RKN Filgerprint is $rkn_sha1_fingerprint\n";
		print {$fh} $file. "\n";
		close $fh;
		exit 1;
		        }
		}
		
		$logger->info("\n\n");
		$logger->info("Got result delta, parsing dump.");
		#
		while(databaseZondStatus())
		{
		    $logger->info("Database not ready, getDumpDeltaList != 1, zond prog is work, waiting for parse dump...");
		}
		#                                        
		set('lasltAction', 'getDumpDelta');
	        set('lastResult', 'req_1');
	        set('lastDumpDate', $actualDate);
	        set('getDumpDeltaList', 0); #сотояние для зонда, сигнал что можно резолвить ip адреса

		# статистика
		$logger->info("Added: domains: ".$added_domains.", urls: ".$added_urls.", IPv4 ips: ".$added_ipv4_ips.", IPv6 ips: ".$added_ipv6_ips.", subnets: ".$added_subnets.", records: ".$added_records);
		$logger->info("Deleted: old records: ".$deleted_old_records);
		$logger->info("Done...");
		getParams();
		getDumpDeltaList();
		
	}
}



sub getDumpDeltaList
{
        $logger->debug("Getting result getDumpDeltaList...");

        my @result;
        eval
        {       
        my @params =  (SOAP::Data->name( 'actualDate' )->type("dateTime")->value($actualDate));
                @result = $soap->getDumpDeltaList(@params);
#                $logger->info(print Dumper(@result));
        };

        if( $@ )
        {
                $logger->fatal("Error while getDumpDeltaList(): ".$@); #тут прилитают http error codes, ждем и вызываем метод заново.
                sleep(60);
                getDumpDeltaList();
        }

        if( !@result )
        {
                $logger->info("Result not defined! getDumpDeltaList");
                $logger->debug( Dumper( @result ));
                sleep(60);
                getDumpDeltaList();
        }

        if( $result[0] == -1 )
        {
        set('lastResult', 'req-1');
        set('lastAction', 'getDumpDeltaList_getResult');
        set('getDumpDeltaList', -1);
	        $logger->info("getDumpDeltaList: -1");
    		getResult();
    		
        }
        elsif( $result[0] == 0)
        {
                $logger->debug("getDumpDeltaList 0");
                set('lastResult', 'req_0');
                set('lastAction', 'getDumpDeltaList_wait60');
                set('actualDate', $actualDate);
                set('getDumpDelta',0); #ждем, чистим deltaId, ничего нет(смотрим тут)
                sleep(60);
                getDumpDeltaList();
        }
        elsif( $result[0] == 1)
        {
        undef %NEW = ();
	undef %OLD = ();
	undef %OLD_ONLY_IPS = ();
	undef %OLD_DOMAINS = ();
	undef %OLD_SUBNETS = ();
	undef %OLD_URLS = ();
	undef %OLD_TRUE = ();
	undef %OLD_TRUE_ONLY_IPS = ();
	undef %OLD_TRUE_DOMAINS = ();
	undef %OLD_TRUE_SUBNETS = ();
	undef %OLD_TRUE_URLS = ();
	undef %getOld = ();
	$resolved_domains_ipv4=0;
	$resolved_domains_ipv6=0;
	$deleted_old_records=0;
	$added_ipv4_ips=0;
	$added_ipv6_ips=0;
	$added_domains=0;
	$added_urls=0;
	$added_subnets=0;
	$added_records=0;

                $actualDate = $result[1]->{actualDate};
                $deltaId = $result[1]->{deltaId};
                $isEmpty = $result[1]->{isEmpty};
                
                if ( $isEmpty eq "true" )
                {
                $actualDate = $result[1]->{actualDate};
                set('actualDate',$actualDate);
                $logger->info("getDumpDeltaList: 1");
                $logger->info("Delta deltaId: $deltaId, isEmpty: $isEmpty, actualDate: $actualDate is store...Next...");
                getDumpDeltaList();
                }
		$logger->info("getDumpDeltaList: 1");
                $logger->info("actualDate: $actualDate, deltaId: $deltaId, isEmpty: $isEmpty");
                set('lastResult', 'req_1');
                set('lastAction', 'getDumpDeltaList_ok');
                set('actualDate', $actualDate);
                set('getDumpDelta',$deltaId);
                set('isEmpty',$isEmpty);
		getParams();
                getDumpDelta($deltaId);
        }
	
    }

sub dbConnect
{
	$DBH = DBI->connect_cached("DBI:mysql:database=".$db_name.";host=".$db_host, $db_user, $db_pass,{mysql_enable_utf8 => 1}) or warn DBI->errstr;
	$DBH->do("set names utf8");
	return 0;
}

sub set
{
	my $param = shift;
	my $value = shift;
	my $sth = $DBH->prepare("UPDATE zap2_settings SET value = ? WHERE param = ?");
	$sth->bind_param(1, $value);
	$sth->bind_param(2, $param);
	$sth->execute or warn DBI->errstr;
}

sub getParams
{
	my $sth = $DBH->prepare("SELECT param,value FROM zap2_settings");
	$sth->execute or warn DBI->errstr;
	while( my $ips = $sth->fetchrow_hashref() )
	{
		my $param=$ips->{param};
		my $value=$ips->{value};
		if($param eq 'lastDumpDate')
		{
			$lastDumpDateOld = $value;
		}
		if($param eq 'lastAction')
		{
			$lastAction = $value;
		}
		if($param eq 'lastCode')
		{
			$lastCode = $value;
		}
		if($param eq 'lastResult' )
		{
			$lastResult = $value;
		}
		if($param eq 'actualDate' )
		{
			$actualDate = $value;
		}
		if($param eq 'getDumpDelta' )
		{
			$deltaId = $value;
		}
		if($param eq 'getDumpDeltaList' )
		{
		$getDumpDeltaList = $value;
		}                                                        
		if($param eq 'isEmpty' )
		{
			$isEmpty = $value;
		}
	}
}

sub databaseZondStatus {
	getParams(); #Вытаскиваем из getDumpDeltaList=? 2=resolver
	    if ( $getDumpDeltaList == 0 )
            {
                set('getDumpDeltaList',1);
        	parseDump();
        	return 0;
            } else
            {
	        sleep(180);
	        set('getDumpDeltaList',0); #закоментировать тут если вы хотите подождать пока отработает zond
            }
}#end sub
                                                                                                    


sub parseDump
{
        $logger->info("Parsing dump...") if ($lastResult eq 'got' || $lastResult eq 'new');
	$logger->info("Parsing dump delta...") if ($lastResult eq 'req_1');

	my $xml = new XML::Simple;
	my $data = '';
	$data = $xml->XMLin($dir.'/dump.xml', ForceArray=> 0, KeyAttr => {});
	$data = $xml->XMLin($dir.'/dump_delta.xml', ForceArray=> 0, KeyAttr => {}) if ($lastResult eq 'req_1');
	my $actualDate = $data->{updateTime};
	my $formatVersion = $data->{formatVersion};
	$logger->info("formatVersion: $formatVersion");
        
	my $ref_del = ref($data->{"delete"});
        eval {
                if($ref_del eq 'ARRAY')
                {
            		foreach my $ref_arr (@{$data->{"delete"}})
            		{
                    		my $delete_id = $ref_arr;
	                        my %delete = ('delete_id' => $delete_id);
    		                $getOld{$delete_id} = \%delete;
            		        $logger->debug("DeleteId ARRAY HASH:".$getOld{$delete_id}{delete_id});
            		}
                }elsif ($ref_del eq 'HASH')
                {
                                my $delete_id = $data->{"delete"};
                                my %delete = ('delete_id' => $delete_id);
                                $getOld{$delete_id} = \%delete;
                                $logger->debug("DeleteId HASH:".$getOld{$delete_id}{delete_id});
                }
        };
        $logger->error("Eval! ".$@) if $@;
#
        my $ref_type = ref($data->{content});
        eval {
                if($ref_type eq 'ARRAY')
                {
                        foreach my $arr (@{$data->{content}})
                        {
                                parseContent($arr);
                        }
                } elsif ($ref_type eq 'HASH')
                {
                        parseContent($data->{content});
                }
        };
        $logger->error("Eval! ".$@) if $@;
        
        # Dump parsed.
	# Get old data from DB
	getOld();
	my $resolver = AnyEvent::DNS->new(timeout => [$dns_timeout], max_outstanding => 50, server => \@resolvers_new); # создаём резолвер с нужными параметрами

	my $cv = AnyEvent->condvar;

	processNew($resolver,$cv);

	proceedOurBlacklist($resolver,$cv) if($our_blacklist ne "");
	if($resolve == 1)
	{
		$logger->debug("Wait while all resolvers finished");

		$cv->recv;
	}
	set('lastAction', 'getResult') if ($lastResult eq 'got');
	set('lastResult', 'req_0') if ($lastResult eq 'req_1');
	set('getDumpDelta', $deltaId) if ($lastResult eq 'req_1');
	set('lastDumpDate', $actualDate);
	set('actualDate', $actualDate);
	set('getDumpDeltaList',0);
}


sub parseContent
{
	my $content = shift;
	my ( $decision_number, $decision_org, $decision_date, $entry_type, $include_time, $block_type );
	$decision_number = $decision_org = $decision_date = $entry_type = '';
	my $decision_id = $content->{id};
	$entry_type = '';

	$decision_number = $content->{decision}->{number} if defined( $content->{decision}->{number} );
	$decision_org = $content->{decision}->{org} if defined( $content->{decision}->{org} );
	$decision_date = $content->{decision}->{date} if defined( $content->{decision}->{org} );
	$entry_type = $content->{entryType} if defined( $content->{entryType} );
	$include_time = $content->{includeTime} if defined( $content->{includeTime} );

	$block_type = $content->{blockType} if(defined($content->{blockType}));

	my %item = (
		'entry_type'	=> $entry_type,
		'decision_num'	=> $decision_number,
		'decision_id'	=> $decision_id,
		'decision_date'	=> $decision_date,
		'decision_org'	=> $decision_org,
		'include_time'	=> $include_time,
		'block_type'	=> $block_type
	);

	my @domains = ();
	my @urls = ();
	my @ips = ();
	my @subnets = ();
	my $blockType=defined($content->{blockType}) ? $content->{blockType} : "default";
	# Domains
	if( defined( $content->{domain} ) )
	{
		if(ref($content->{domain}) eq 'ARRAY')
		{
			foreach my $domain (@{$content->{domain}})
			{
				if(ref($domain) eq 'HASH')
				{
					push @domains, $domain->{content};
				} else {
					push @domains, $domain;
				}
			}
		} elsif (ref($content->{domain}) eq 'HASH')
		{
			push @domains, $content->{domain}->{content};
		} else {
			push @domains, $content->{domain};
		}
	}
	$item{'domains'} = \@domains;

	# URLs
	if( defined( $content->{url} ) )
	{
		if( ref($content->{url}) eq 'ARRAY' )
		{
			foreach my $url (@{$content->{url}})
			{
				if(ref($url) eq 'HASH')
				{
					push @urls, $url->{content};
				} else {
					push @urls, $url;
				}
			}
		} elsif (ref($content->{url}) eq 'HASH')
		{
			push @urls, $content->{url}->{content};
		} else {
			push @urls, $content->{url};
		}
	}
	$item{'urls'} = \@urls;

	# IPs
	if( defined( $content->{ip} ) )
	{
		if( ref($content->{ip}) eq 'ARRAY' )
		{
			foreach my $ip (@{$content->{ip}})
			{
				if(ref($ip) eq 'HASH')
				{
					push @ips, $ip->{content};
				} else {
					push @ips, $ip;
				}
			}
		} elsif(ref($content->{ip}) eq 'HASH')
		{
			push @ips, $content->{ip}->{content};
		} else {
			push @ips, $content->{ip};
		}
	}
	$item{'ips'} = \@ips;

	# Subnets
	if( defined( $content->{ipSubnet} ) )
	{
		if( ref($content->{ipSubnet}) eq 'ARRAY' )
		{
			foreach my $subnet ( @{$content->{ipSubnet}} )
			{
				if(ref($subnet) eq 'HASH')
				{
					push @subnets, $subnet->{content};
				} else {
					push @subnets, $subnet;
				}
			}
		} elsif (ref($content->{ipSubnet}) eq 'HASH')
		{
			push @subnets, $content->{ipSubnet}->{content};
		} else {
			push @subnets, $content->{ipSubnet};
		}
	}
	$item{'subnets'} = \@subnets;

	$NEW{$decision_id} = \%item;
}


sub processNew {
	my $resolver = shift;
	my $cv = shift;
	my $sth;
    eval {
	# Content items:
	foreach my $d_id ( keys %NEW ) {
		
		my $record_id = 0;
		if( !defined( $OLD{$d_id} ) )
		{
			# New record
			$sth = $DBH->prepare("INSERT INTO zap2_records(decision_id,decision_date,decision_num,decision_org,include_time,entry_type) VALUES(?,?,?,?,?,?)");
			$sth->bind_param(1, $d_id );
			$sth->bind_param(2, $NEW{$d_id}->{decision_date} );
			$sth->bind_param(3, $NEW{$d_id}->{decision_num} );
			$sth->bind_param(4, $NEW{$d_id}->{decision_org} );
			$sth->bind_param(5, $NEW{$d_id}->{include_time} );
			$sth->bind_param(6, $NEW{$d_id}->{entry_type} );
			$sth->execute;
			$record_id = $sth->{mysql_insertid};
			$OLD{$d_id} = $record_id;
			$logger->info("Added new content: id: $d_id and record_id ".$record_id);
			$added_records++;
		} else {
			delete $OLD_TRUE{$d_id};
			$record_id = $OLD{$d_id}->{id};
		}

		# URLs
		my $processed_urls=0;
		if( ref($NEW{$d_id}->{urls}) eq 'ARRAY' )
		{
			foreach my $url ( @{$NEW{$d_id}->{urls}} )
			{
				$processed_urls++;
				# Check for ex. domain
				my $uri = URI->new($url);
				my $scheme = $uri->scheme();
				if($scheme ne "http" && $scheme ne "https")
				{
					$logger->warn("Unsupported scheme in the url: $url");
				} else {
					my $url_domain = $uri->host();
					#my @res = ( $url =~ m!^(?:http://|https://)?([^(/|\?)]+)!i );
					#my $url_domain = $res[0];
					if( defined( $EX_DOMAINS{$url_domain} ) ) {
	#					binmode(STDOUT, ':utf8');
	#					print "EXCLUDE DOMAIN ".$url_domain." (URL ".$url.")\n";
						next;
					}
					Resolve( $url_domain, $record_id, $resolver, $cv);
				}
				
				
				if( !defined( $OLD_URLS{md5_hex(encode_utf8($url))} ) ) {
#				    binmode(STDOUT, ':utf8');
#				    print "New URL: ".encode_utf8($url)."\n";
#				    print "MD5 hex: ".md5_hex(encode_utf8($url))."\n";
				    $sth = $DBH->prepare("INSERT INTO zap2_urls(record_id, url) VALUES(?,?)");
				    $sth->bind_param(1, $record_id);
				    $sth->bind_param(2, $url);
				    $sth->execute;
				    $OLD_URLS{md5_hex(encode_utf8($url))} = 1;
				    $logger->info("Added new URL: ".$url." id: $d_id and record_id: $record_id");
				    $added_urls++;
				} else {
					# delete from old_true_urls
					delete $OLD_TRUE_URLS{md5_hex(encode_utf8($url))};
				}
			}
		}
		my $need_to_block_domain=0;
		if(!$processed_urls)
		{
			$logger->info("Item $d_id hasn't defined URL, must block by DOMAIN");
			$need_to_block_domain=1;
		}
		
		my $processed_domains=0;
		# Domain items:
		if( ref($NEW{$d_id}->{domains}) eq 'ARRAY' && $need_to_block_domain)
		{
			foreach my $domain( @{$NEW{$d_id}->{domains}} )
			{
				# Check for excludes
				if( defined( $EX_DOMAINS{$domain} ) ) {
	#				print "EXCLUDE DOMAIN: ".$domain."\n";
					$logger->info("Excluding domain: ".$domain);
					next;
				}
				$processed_domains++;
				if($domain =~ /^\*\./)
				{
					$logger->info("Skip to resolve domain '$domain' because it masked, id: $d_id and record_id: $record_id");
				} else {
					Resolve( $domain, $record_id, $resolver, $cv );
				}
				if( !defined( $OLD_DOMAINS{md5_hex(encode_utf8($domain))} ) )
				{
#					print "New domain: ".$domain."\n";
					$sth = $DBH->prepare("INSERT INTO zap2_domains(record_id, domain) VALUES(?,?)");
					$sth->bind_param(1, $record_id);
					$sth->bind_param(2, $domain);
					$sth->execute;
					$OLD_DOMAINS{md5_hex(encode_utf8($domain))} = 1;
					$logger->info("Added new domain ".$domain." id: $d_id and record_id: $record_id");
					$added_domains++;
				} else {
					delete $OLD_TRUE_DOMAINS{md5_hex(encode_utf8($domain))};
				}
			}
		}
		my $need_to_block_ip=0;
		if(!$processed_urls && !$processed_domains)
		{
			$logger->info("Item $d_id hasn't url and domain, need to block by IP");
			$need_to_block_ip=1;
		}

		# IPS
		if( ref($NEW{$d_id}->{ips}) eq 'ARRAY' )
		{
			foreach my $ip ( @{$NEW{$d_id}->{ips}} )
			{
			    next if(!defined $ip);
				if($need_to_block_ip)
				{
					if( !defined( $OLD_ONLY_IPS{$ip} ) )
					{
						my $ipa = new Net::IP($ip);
						my $ip_packed=pack("B*",$ipa->binip());
						$sth = $DBH->prepare("INSERT INTO zap2_only_ips(record_id, ip) VALUES(?,?)");
						$sth->bind_param(1, $record_id);
						$sth->bind_param(2, $ip_packed);
						$sth->execute;
						$OLD_ONLY_IPS{$ipa->ip()} = 1;
						$logger->info("ADD New ONLY ip: ".$ipa->ip()." and id: $d_id to record_id: $record_id");
						$added_ipv4_ips++;
					} else {
						delete $OLD_TRUE_ONLY_IPS{$ip};
					}
					next;
				}
				my $exclude = 0;
				# Check excluded nets
				for my $subnet (keys %EX_SUBNETS) {
					my $ipadr = NetAddr::IP->new( $ip );
					my $net = NetAddr::IP->new( $subnet );
					if( $ipadr && $net ) {
						if( $ipadr->within($net) ) {
#							print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
							$logger->info("Excluding ip ".$ip);
							$exclude = 1;
							last;
						}
					}
				}
				next if( $exclude == 1 );
				
				# Check for ex. ip
				if( defined($EX_IPS{$ip}) )
				{
#					print "Excluding ip ".$ip.": match excluded ip in DB.\n";
					$logger->info("Excluding ip ".$ip);
					next;
				}
				
				if( !defined( $ZAP_OLD_IPS{$record_id}{$ip} ) )
				{
#					print "New ip: ".$ip."\n";
					my $ipa = new Net::IP($ip);
					my $ip_packed=pack("B*",$ipa->binip());
					$sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved) VALUES(?,?,0)");
					$sth->bind_param(1, $record_id);
					$sth->bind_param(2, $ip_packed);
					$sth->execute;
					$ZAP_OLD_IPS{$record_id}{$ipa->ip()} = 1;
					$logger->info("ADD New ip: ".$ipa->ip()." and id: $d_id to record_id: $record_id");
					if($ipa->version() == 4)
					{
						$added_ipv4_ips++;
					} else {
						$added_ipv6_ips++;
					}
				} else {
					delete $ZAP_OLD_TRUE_IPS{$record_id}{$ip};
				}
			}
		}

		# Subnets
		if( ref($NEW{$d_id}->{subnets}) eq 'ARRAY' )
		{
			foreach my $subnet ( @{$NEW{$d_id}->{subnets}} )
			{
				my $exclude = 0;
				# Check for excludes. Ips:
				for my $ip (keys %EX_IPS)
				{
#					print $ip."\n";
					my $ipadr = NetAddr::IP->new( $ip );
					my $net = NetAddr::IP->new( $subnet );
					if( $ipadr && $net ) {
						if( $ipadr->within($net) ) {
#							print "Exclude subnet ".$subnet.": contains excluded IP ".$ip."\n";
							$logger->debug("Excluding subnet ".$subnet);
							$exclude = 1;
						}
					}
				}
				# And nets:
				for my $net (keys %EX_SUBNETS)
				{
					my $net1 = NetAddr::IP->new( $net );
					my $net2 = NetAddr::IP->new( $subnet );
					if( $net1 && $net2 ) {
						if( $net1->within( $net2 ) || $net2->within( $net1 ) ) {
#							print "Exclude subnet ".$subnet.": overlaps with excluded net ".$net."\n";
							$exclude = 1;
							$logger->info("Excluding subnet ".$subnet);
							last;
						}
					}
				}
				
				if( $exclude == 1 ) {
					next;
				}
				
				if( !defined( $OLD_SUBNETS{$subnet} ) )
				{
#					print "New subnet: ".$subnet."\n";
					$sth = $DBH->prepare("INSERT INTO zap2_subnets(record_id, subnet) VALUES(?,?)");
					$sth->bind_param(1, $record_id);
					$sth->bind_param(2, $subnet);
					$sth->execute;
					$OLD_SUBNETS{$subnet} = 1;
					$logger->info("Added new subnet: ".$subnet." and id: ".$d_id);

					# Check, if there no any othere parameters in this content
					if(
						( !defined($NEW{$d_id}->{domains}) || ref($NEW{$d_id}->{domains}) ne 'ARRAY' || scalar(@{$NEW{$d_id}->{domains}}) == 0 )
						&&
						( !defined($NEW{$d_id}->{urls}) || ref($NEW{$d_id}->{urls}) ne 'ARRAY' || scalar(@{$NEW{$d_id}->{urls}}) == 0 )
					) {
					}
					$added_subnets++;
				} else {
					delete $OLD_TRUE_SUBNETS{$subnet};
				}
			}
		}
		
	}
    };
	$logger->error("Eval: ".$@) if $@;

}

sub proceedOurBlacklist
{
	my $resolver = shift;
	my $cv = shift;
	my %OLD_BLACKLIST;
	my %OLD_BLACKLIST_DEL;
	my $sth;
	eval {
		# filling old records...
		$sth = $DBH->prepare("SELECT id,decision_num FROM zap2_records WHERE decision_id = 0 ORDER BY date_add");
		$sth->execute or warn DBI->errstr;
		while( my $ips = $sth->fetchrow_hashref() )
		{
			$OLD_BLACKLIST{$ips->{decision_num}}=$ips->{id};
			$OLD_BLACKLIST_DEL{$ips->{decision_num}}=$ips->{id};
		}

		my $record_id;

		open (my $fh, $our_blacklist);
		while (my $url = <$fh>)
		{
			chomp $url;
			my $md_hex=md5_hex(encode_utf8($url));
			if(defined $OLD_BLACKLIST{$md_hex})
			{
				$record_id=$OLD_BLACKLIST{$md_hex};
				delete $OLD_BLACKLIST_DEL{$md_hex};
			} else {
				$sth = $DBH->prepare("INSERT INTO zap2_records(decision_num,decision_org,decision_id) VALUES(?,?,?)");
				$sth->bind_param(1,$md_hex);
				$sth->bind_param(2,"our_blacklist");
				$sth->bind_param(3,0);
				$sth->execute;
				$record_id = $sth->{mysql_insertid};
				$OLD_BLACKLIST{$md_hex}=$record_id;
				$logger->info("Added new content from our blacklist: id ".$record_id);
				$added_records++;
			}
			my $uri = URI->new($url);
			my $scheme = $uri->scheme();
			if($scheme ne "http" && $scheme ne "https")
			{
				$logger->info("Unsupported scheme in url: $url for resolving.");
			} else {
				my $url_domain = $uri->host();
				if( defined( $EX_DOMAINS{$url_domain} ) )
				{
					$logger->info("Excluding URL (caused by excluded domain $url_domain): $url");
					next;
				}
				Resolve( $url_domain, $record_id, $resolver, $cv);
			}
			if( !defined( $OLD_URLS{md5_hex(encode_utf8($url))} ) ) {
				$sth = $DBH->prepare("INSERT INTO zap2_urls(record_id, url) VALUES(?,?)");
				$sth->bind_param(1, $record_id);
				$sth->bind_param(2, $url);
				$sth->execute;
				$OLD_URLS{md5_hex(encode_utf8($url))} = 1;
				$logger->info("Added new URL: ".$url);
				$added_urls++;
			} else {
				# delete from old_true_urls
				delete $OLD_TRUE_URLS{md5_hex(encode_utf8($url))};
			}
		}
		close $fh;

		# delete old records..
		foreach my $key (keys %OLD_BLACKLIST_DEL)
		{
			$deleted_old_records++;
			delRecord($OLD_BLACKLIST_DEL{$key});
		}
	};
	$logger->error("proceedOurBlackkist: ".$@) if $@;
}

sub getOld {
	%OLD = ();
	%OLD_ONLY_IPS = ();
	%OLD_DOMAINS = ();
	%OLD_SUBNETS = ();
	%OLD_URLS = ();
	%OLD_TRUE = ();
	%OLD_TRUE_ONLY_IPS = ();
	%OLD_TRUE_DOMAINS = ();
	%OLD_TRUE_SUBNETS = ();
	%OLD_TRUE_URLS = ();
	# Contents
	my $sth = $DBH->prepare("SELECT id,date_add,decision_id,decision_date,decision_num,decision_org,include_time FROM zap2_records WHERE decision_id > 0 ORDER BY date_add");
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
	
		my %item = (
			'id' => $$ref[0],
			'date_add' => $$ref[1],
			'decision_id' => $$ref[2],
			'decision_date' => $$ref[3],
			'decision_num' => $$ref[4],
			'decision_org' => $$ref[5],
			'include_time' => $$ref[6]
		);
		$OLD{$$ref[2]} = \%item;
		$OLD_TRUE{$$ref[2]} = \%item;
		my $del_decision_id = $$ref[2];
		my $del_id = $$ref[0];
	
		foreach my $del (keys %getOld) {

			if ( $getOld{$del}{delete_id}{id} eq $del_decision_id ) {
				delDomain($del_id);
				delUrl($del_id);
				delIp($del_id);
				delIpOnly($del_id);
				delSubnet($del_id);
				delRecord($del_id);
				$logger->info("Delete RecordId: ".$del_id." DecisionId: ".$del_decision_id);
				$deleted_old_records++;
			}
		}
	} #end while
	
	# Domains
	$sth = $DBH->prepare("SELECT record_id, domain, id FROM zap2_domains ORDER BY date_add");
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_DOMAINS{md5_hex(encode_utf8($$ref[1]))} = $$ref[0];
		@{$OLD_TRUE_DOMAINS{md5_hex(encode_utf8($$ref[1]))}} = ( $$ref[2], $$ref[1], $$ref[0] );
	}
	
	# URLs
	$sth = $DBH->prepare("SELECT id,record_id,url FROM zap2_urls ORDER BY date_add");
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_URLS{md5_hex(encode_utf8($$ref[2]))} = $$ref[0];
		@{$OLD_TRUE_URLS{md5_hex(encode_utf8($$ref[2]))}} = ( $$ref[0], $$ref[2], $$ref[1] );
	}
	
	# Subnets
	$sth = $DBH->prepare("SELECT record_id, subnet, id FROM zap2_subnets ORDER BY date_add");
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_SUBNETS{$$ref[1]} = $$ref[0];
		@{$OLD_TRUE_SUBNETS{$$ref[1]}} = ( $$ref[2], $$ref[1] );
	}
	
	# Ips
	$sth = $DBH->prepare("SELECT ip, record_id, id, resolved FROM zap2_ips ORDER BY date_add");
	$sth->execute or warn DBI->errstr;
	while( my $ips = $sth->fetchrow_hashref() )
	{
		my $old_ip=get_ip($ips->{ip});
		$ZAP_OLD_IPS{$ips->{record_id}}{$old_ip}=$ips->{id};
		next if($keep_resolved == 1 && $ips->{resolved} eq "1"); # skeep to delete resolved ips
		$ZAP_OLD_TRUE_IPS{$ips->{record_id}}{$old_ip}=$ips->{id};
	}

	# ONLY ips
	$sth = $DBH->prepare("SELECT ip, record_id, id FROM zap2_only_ips ORDER BY date_add");
	# todo добавить поддержку ipv6
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref )
	{
		my $old_ip=get_ip($$ref[0]);
		$OLD_ONLY_IPS{$old_ip} = $$ref[1];
		@{$OLD_TRUE_ONLY_IPS{$old_ip}} = ( $$ref[2], $old_ip );
	}
	
	# Excludes
	$sth = $DBH->prepare("SELECT subnet FROM zap2_ex_nets");
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_SUBNETS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT inet_ntoa(ip) FROM zap2_ex_ips");
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_IPS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT domain FROM zap2_ex_domains");
	$sth->execute or warn DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_DOMAINS{$$ref[0]} = 1;
	}
}

sub Resolve
{
	my $domain = shift;
	my $record_id = shift;
	my $resolvera = shift || undef;
	my $cv=shift || undef;

	if( $resolve != 1 ) {
		return;
	}

	if(defined $resolver_cache{md5_hex(encode_utf8($domain))})
	{
		$logger->debug("Domain $domain already resolved");
		return;
	}
	$resolver_cache{md5_hex(encode_utf8($domain))}=1;
	resolve_async($cv,$domain,$resolvera,$record_id);
}


sub delDomain {
	my $id = shift;
#	my $domain = shift;
	
#	$logger->debug("Removing domain $domain and $id");
	
	my $sth = $DBH->prepare("DELETE FROM zap2_domains WHERE record_id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delUrl {
	my $id = shift;
#	my $url = shift;

#	$logger->debug("Removing URL $url and id $id");
	
	my $sth = $DBH->prepare("DELETE FROM zap2_urls WHERE record_id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delIp
{
	my $id = shift;
#	my $ip = shift;
	
#	$logger->debug("Removing IP $ip and id $id");
	
	my $sth = $DBH->prepare("DELETE FROM zap2_ips WHERE record_id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delIpOnly {
	my $id = shift;
#	my $ip = shift;
	
#	$logger->debug("Removing ONLY IP $ip and id $id");
	
	my $sth = $DBH->prepare("DELETE FROM zap2_only_ips WHERE record_id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delSubnet {
	my $id = shift;
#	my $subnet = shift;

#	$logger->debug("Removing subnet $subnet and id $id");
	
	my $sth = $DBH->prepare("DELETE FROM zap2_subnets WHERE record_id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub delRecord {
	my $id = shift;
	
	$logger->debug("Removing record id ".$id);
	
	my $sth = $DBH->prepare("DELETE FROM zap2_records WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
}

sub get_ip
{
	my $ip_address=shift;
	my $d_size=length($ip_address);
	my $result;
	if($d_size == 4)
	{
		$result=ip_bintoip(unpack("B*",$ip_address),4);
	} else {
		$result=ip_bintoip(unpack("B*",$ip_address),6);
	}
	return $result;
}

sub resolve_async
{
	my $cv=shift;
	my $host=shift;
	my $resolver=shift;
	my $record_id=shift;
	if($host =~ m/([А-Яа-я]+)/gi )
	{
		$host=puny_enc($host);
	}
	$cv->begin;
	$resolver->resolve($host, "a", accept => ["a"], sub {
		$resolved_domains_ipv4++;
		for my $record (@_) {
			my $nr=scalar(@$record);
			my $ipa = new Net::IP($record->[$nr-1]);
			if(!defined($ipa))
			{
				$logger->info( "Invalid ipv4 address ".$record->[$nr-1]." for domain $host");
				next;
			}
			my $ip=$ipa->ip();
			if( defined( $ZAP_OLD_IPS{$record_id}{$ip} ) )
			{
				# delete from old, because we have it.
				delete $ZAP_OLD_TRUE_IPS{$record_id}{$ip} if(defined $ZAP_OLD_TRUE_IPS{$record_id}{$ip});
				next;
			}
			if ($ipa->iptype() ne "PUBLIC" && $ipa->iptype() ne "GLOBAL-UNICAST")
			{
				$logger->info("Bad ip type: ".$ipa->iptype()." for ipv4 $ip host $host");
				next;
			}
			my $exclude = 0;
			for my $subnet (keys %EX_SUBNETS)
			{
				my $ipadr = NetAddr::IP->new( $ip );
				my $net = NetAddr::IP->new( $subnet );
				if( $ipadr && $net ) {
					if( $ipadr->within($net) ) {
						#print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
						$logger->info("Excluding ipv4 ".$ip);
						$exclude = 1;
						last;
					}
				}
			}
			if( defined($EX_IPS{$ip}) )
			{
				$logger->debug("Excluding ipv4 ".$ip);
				$exclude = 1;
			}
		
			if( $exclude == 1 ) {
				next;
			}
			if($ipa->version() == 4)
			{
				$added_ipv4_ips++;
			} else {
				$added_ipv6_ips++;
			}
			my $ip_packed=pack("B*",$ipa->binip());
			# Not in old ips, not in excludes...
			my $sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved, domain) VALUES(?,?,1,?)");
			$sth->bind_param(1, $record_id);
			$sth->bind_param(2, $ip_packed);
			$sth->bind_param(3, $host);
			$sth->execute;
			$logger->info("New resolved ipv4: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id);
			$ZAP_OLD_IPS{$record_id}{$ipa->ip()} = 1;
		}
		$cv->end;
	});

	if($ipv6_nslookup)
	{
		$cv->begin;
		$resolver->resolve($host, "aaaa", accept => ["aaaa"], sub {
		$resolved_domains_ipv6++;
		for my $record (@_) {
			my $nr=scalar(@$record);
			my $ipa = new Net::IP($record->[$nr-1]);
			if(!defined($ipa))
			{
				$logger->info( "Invalid ipv6 address ".$record->[$nr-1]." for domain $host");
				next;
			}
			my $ip=$ipa->ip();
			if( defined( $ZAP_OLD_IPS{$record_id}{$ip} ) )
			{
				# delete from old, because we have it.
				delete $ZAP_OLD_TRUE_IPS{$record_id}{$ip} if(defined $ZAP_OLD_TRUE_IPS{$record_id}{$ip});
				next;
			}
			if ($ipa->iptype() ne "PUBLIC" && $ipa->iptype() ne "GLOBAL-UNICAST")
			{
				$logger->info("Bad ip type: ".$ipa->iptype()." for ipv6 $ip host $host");
				next;
			}
			my $exclude = 0;
			for my $subnet (keys %EX_SUBNETS)
			{
				my $ipadr = NetAddr::IP->new( $ip );
				my $net = NetAddr::IP->new( $subnet );
				if( $ipadr && $net ) {
					if( $ipadr->within($net) ) {
						#print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
						$logger->info("Excluding ipv6 ".$ip);
						$exclude = 1;
						last;
					}
				}
			}
			if( defined($EX_IPS{$ip}) )
			{
				$logger->debug("Excluding ip ".$ip);
				$exclude = 1;
			}
		
			if( $exclude == 1 ) {
				next;
			}
			if($ipa->version() == 4)
			{
				$added_ipv4_ips++;
			} else {
				$added_ipv6_ips++;
			}
			my $ip_packed=pack("B*",$ipa->binip());
			# Not in old ips, not in excludes...
			my $sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved, domain) VALUES(?,?,1,?)");
			$sth->bind_param(1, $record_id);
			$sth->bind_param(2, $ip_packed);
			$sth->bind_param(3, $host);
			$sth->execute;
			$logger->info("New resolved ip: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id);
			$ZAP_OLD_IPS{$record_id}{$ipa->ip()} = 1;
		}
		$cv->end;
		});
	}

}

END
{
    $pidfile->remove if defined $pidfile;
}
