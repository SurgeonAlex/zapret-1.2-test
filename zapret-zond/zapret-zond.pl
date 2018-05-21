#!/usr/bin/perl -w

use strict;
use warnings;
use File::Basename 'dirname';
use File::Spec;
use lib join '/',File::Spec->splitdir(dirname(__FILE__));
use DBI;
use Data::Dumper;
use utf8;
use URI 1.69;
use NetAddr::IP;
use Digest::MD5 qw(md5_hex);
use Encode qw(decode_utf8 encode_utf8);
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


binmode(STDOUT,':utf8');
binmode(STDERR,':utf8');


######## Config #########

my $dir = File::Basename::dirname($0);
my $Config = {};

my $config_file=$dir.'/zapret-zond.conf';
my $force_load='';
my $log_file=$dir."/zapret-zond_log.conf";

GetOptions("force_load" => \$force_load,
	    "log=s" => \$log_file,
	    "config=s" => \$config_file) or die "Error no command line arguments\n";

Config::Simple->import_from($config_file, $Config) or die "Can't open ".$config_file." for reading!\n";

Log::Log4perl::init( $log_file );

my $logger=Log::Log4perl->get_logger();

$logger->info("\n\n");

my $db_host = $Config->{'DB.host'} || die "DB.host not defined.";
my $db_user = $Config->{'DB.user'} || die "DB.user not defined.";
my $db_pass = $Config->{'DB.password'} || die "DB.password not defined.";
my $db_name = $Config->{'DB.name'} || die "DB.name not defined.";

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


my $our_blacklist = $Config->{'PATH.our_blacklist'} || "";

######## End config #####

my $DBH;
my ($lastDumpDateOld, $lastAction, $lastCode, $lastResult, $actualDate, $deltaId, $isEmpty, $getDumpDeltaList);
dbConnect();

getParams();
if ($lastResult eq 'new'){
$logger->info("Virguzka script status is getResult, waiting server zapretd of resolver finished!!!");
exit 1;
}

my %NEW = ();
my %OLD = ();
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
my $added_ipv4_ips=0;
my $added_ipv6_ips=0;
my $added_domains=0;
my $added_urls=0;
my $added_subnets=0;
my $added_records=0;

#############################################################
while(start()) {
	$logger->info("Database not ready, getDumpDeltaList=1, waiting...");
} #end while

sub start {
	    getParams(); #Вытаскиваем из getDumpDeltaList=? 0 начать резолвинг адресов, 1 ждем
	    if ( $getDumpDeltaList == 0 )
	    {
		    set('getDumpDeltaList', 2); #ставим метку 1 чтобы небыло конкурентов(что бы др. зонды и zapretd не писали в базу),снимаем метку как все закончим.
		    my $start_time=localtime();
		    $logger->info("Starting zapret-zond program ".$start_time);
		    getResult();
		    set('getDumpDeltaList', 0); # Сняли конкурентную метку.
		    return 0;
	    } else {
	    sleep(60);
	    }
}#end sub

sub getResult
{
	$logger->debug("Getting result...");
		parseDump();
		$logger->info("Resolved domains ipv4: ".$resolved_domains_ipv4.", resolved domains ipv6: ".$resolved_domains_ipv6);
		$logger->info("Added: IPv4 ips: ".$added_ipv4_ips.", IPv6 ips: ".$added_ipv6_ips);
		my $stop_time=localtime();
		$logger->info("Stop zapret-zond program ".$stop_time);
	return 0;
}

sub dbConnect
{
	$DBH = DBI->connect_cached("DBI:mysql:database=".$db_name.";host=".$db_host, $db_user, $db_pass,{mysql_enable_utf8 => 1}) or die DBI->errstr;
	$DBH->do("set names utf8");
}

sub set
{
        my $param = shift;
        my $value = shift;
        my $sth = $DBH->prepare("UPDATE zap2_settings SET value = ? WHERE param = ?");
        $sth->bind_param(1, $value);
        $sth->bind_param(2, $param);
        $sth->execute or die DBI->errstr;
}


sub getParams
{
        my $sth = $DBH->prepare("SELECT param,value FROM zap2_settings");
        $sth->execute or die DBI->errstr;
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


sub parseDump
{
	$logger->info("Wait, Database training...");
	#Тут определяем старые, заранее нельзя, может прилитель дельта и сломаться mysql_insert_id
	getOld();

	my $resolver = AnyEvent::DNS->new(timeout => [$dns_timeout], max_outstanding => 50, server => \@resolvers_new); # создаём резолвер с нужными параметрами

	my $cv = AnyEvent->condvar;

	processNew($resolver,$cv);

	if($resolve == 1)
	{
		$logger->info("Wait while all resolvers finished");

		$cv->recv;
	$logger->info("All resolvers finished correctly!");
	}

}


sub processNew {
	my $resolver = shift;
        my $cv = shift;
        my $url_domain;
        my $domains;
        my $dm;
        
        foreach my $domain ( keys %OLD_TRUE_DOMAINS ) {
            my $record_id = $OLD_TRUE_DOMAINS{$domain}[0];
            $domains = decode_utf8($OLD_TRUE_DOMAINS{$domain}[1]);

           if( defined( $EX_DOMAINS{$domains} ) ) {
              $logger->info("Excluding domain (caused by excluded domain $domains ): $domains");
               next;
           }
           if($domains =~ /^\*\./)
           {
           $dm = $domains;
           $dm =~ s/\*\.//g;
           Resolve( $dm, $record_id, $resolver, $cv );
                        $logger->info("Resolving masked domain id ".$OLD_TRUE_DOMAINS{$domain}[0]." ( ".$OLD_TRUE_DOMAINS{$domain}[1]." )");
           } else {
           Resolve( $domains, $record_id, $resolver, $cv );
           $logger->debug("New Resolving domain id ".$OLD_TRUE_DOMAINS{$domain}[0]." ( ".$OLD_TRUE_DOMAINS{$domain}[1]." )");
           }
       } #end foreach
       
       foreach my $url ( keys %OLD_TRUE_URLS ) {
	       my $record_id = $OLD_TRUE_URLS{$url}[0];
	       my $urls = decode_utf8($OLD_TRUE_URLS{$url}[1]);
	       $urls = URI->new($urls);
	       my $scheme = $urls->scheme();
       
               if($scheme ne "http" && $scheme ne "https") {
	       $logger->debug("Unsupported scheme in url: $urls for resolving.");
               }
               else {
	       $url_domain = $urls->host();

                   if( defined( $EX_DOMAINS{$url_domain} ) ) {
	           $logger->info("Excluding URL (caused by excluded domain $url_domain): $urls");
                   next;
                   }
               Resolve( $url_domain, $record_id, $resolver, $cv);
              }#end_else
	       $logger->debug("New Resolving url id ".$OLD_TRUE_URLS{$url}[0]." (".$OLD_TRUE_URLS{$url}[1].")");
       }

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
	$sth->execute or die DBI->errstr;
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
	}
	
	# Domains
	$sth = $DBH->prepare("SELECT record_id, domain, id FROM zap2_domains ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_DOMAINS{md5_hex(encode_utf8($$ref[1]))} = $$ref[0];
		@{$OLD_TRUE_DOMAINS{md5_hex(encode_utf8($$ref[1]))}} = ( $$ref[2], $$ref[1], $$ref[0] );
	}
	
	# URLs
	$sth = $DBH->prepare("SELECT id,record_id,url FROM zap2_urls ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_URLS{md5_hex(encode_utf8($$ref[2]))} = $$ref[0];
		@{$OLD_TRUE_URLS{md5_hex(encode_utf8($$ref[2]))}} = ( $$ref[0], $$ref[2], $$ref[1] );
	}

        # Subnets
        $sth = $DBH->prepare("SELECT record_id, subnet, id FROM zap2_subnets ORDER BY date_add");
        $sth->execute or die DBI->errstr;
        while( my $ref = $sth->fetchrow_arrayref ) {
                $OLD_SUBNETS{$$ref[1]} = $$ref[0];
                @{$OLD_TRUE_SUBNETS{$$ref[1]}} = ( $$ref[2], $$ref[1] );
        }

        # Ips
        $sth = $DBH->prepare("SELECT ip, record_id, id, resolved FROM zap2_ips ORDER BY date_add");
        $sth->execute or die DBI->errstr;
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
        $sth->execute or die DBI->errstr;
        while( my $ref = $sth->fetchrow_arrayref )
        {
                my $old_ip=get_ip($$ref[0]);
                $OLD_ONLY_IPS{$old_ip} = $$ref[1];
                @{$OLD_TRUE_ONLY_IPS{$old_ip}} = ( $$ref[2], $old_ip );
        }

	# Excludes
	$sth = $DBH->prepare("SELECT subnet FROM zap2_ex_nets");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_SUBNETS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT inet_ntoa(ip) FROM zap2_ex_ips");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_IPS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT domain FROM zap2_ex_domains");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_DOMAINS{$$ref[0]} = 1;
	}
	$logger->info("List of DB finished!");
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
                                $logger->info( "Invalid ip address ".$record->[$nr-1]." for domain $host");
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
                                $logger->info("Bad ip type: ".$ipa->iptype()." for ip $ip host $host");
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
                                                $logger->info("Excluding new ip: $ip, record_id: $record_id");
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
                        $logger->info("New resolved IP: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id);
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
                                $logger->info("Bad ip type: ".$ipa->iptype()." for ip $ip host $host");
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
                                                $logger->info("Excluding new ipv6 $ip and record_id: $record_id");
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
                        $logger->info("New resolved IPv6: ".$ipa->ip()." for domain ".$host." record_id: ".$record_id);
                        $ZAP_OLD_IPS{$record_id}{$ipa->ip()} = 1;
                }
                $cv->end;
                });
        }

}

