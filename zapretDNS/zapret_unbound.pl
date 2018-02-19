#!/usr/bin/perl
#####RKN#### unbound.conf
#include: /etc/unbound/forward.conf
#include: /etc/unbound/domains_mask.conf
###########

# создаем нужные файлы из БД rkn

use strict;
use warnings;
use utf8;
use Config::Simple;
use File::Basename;
use DBI;
use URI;
use POSIX;
use Digest::MD5 qw (md5);
use Log::Log4perl;

binmode(STDOUT,':utf8');
binmode(STDERR,':utf8');

my $dir = File::Basename::dirname($0);

my $Config = {};
Config::Simple->import_from($dir.'/zapret_unbound.conf', $Config) or die "Can't open ".$dir."/zapret_unbound.conf for reading!\n";

Log::Log4perl::init( $dir."/zapret_unbound_log.conf" );
my $logger=Log::Log4perl->get_logger();

my $db_host = $Config->{'DB.host'} || die "DB.host not defined.";
my $db_user = $Config->{'DB.user'} || die "DB.user not defined.";
my $db_pass = $Config->{'DB.password'} || die "DB.password not defined.";
my $db_name = $Config->{'DB.name'} || die "DB.name not defined.";

# пути к генерируемым файлам:
my $domains_file = $Config->{'APP.domains'} || "";
my $domains_mask_file = $Config->{'APP.domains_mask'} || "";

my $dbh = DBI->connect("DBI:mysql:database=".$db_name.";host=".$db_host,$db_user,$db_pass,{mysql_enable_utf8 => 1}) or die DBI->errstr;
$dbh->do("set names utf8");

my $domains_file_hash_old=get_md5_sum($domains_file);

open (my $DOMAINS_FILE, ">",$domains_file) or die "Could not open DOMAINS '$domains_file' file: $!";
open (my $DOMAINS_MASK_FILE, ">", $domains_mask_file) or die "Could not open file '$domains_mask_file' file: $!";

my $cur_time=strftime "%F %T", localtime $^T;

my $n_masked_domains = 0;
my %masked_domains;

my $sth = $dbh->prepare("SELECT * FROM zap2_domains WHERE domain like '*.%'");
$sth->execute();
while (my $ips = $sth->fetchrow_hashref())
{
	my $dm = $ips->{domain};
	$dm =~ s/\*\.//g;
	my $domain_canonical=new URI("http://".$dm)->canonical();
	$domain_canonical =~ s/^http\:\/\///;
	$domain_canonical =~ s/\/$//;
	$domain_canonical =~ s/\.$//;
	next if($domain_canonical =~ /xn--/i);
	$masked_domains{$domain_canonical} = 1;
	$n_masked_domains++;

       print $DOMAINS_MASK_FILE 'local-data: "', $domain_canonical,'. 3600 IN A your-ip-addr-here"', "\n";
       print $DOMAINS_MASK_FILE 'local-zone: "', $domain_canonical,'." redirect', "\n";
}
$sth->finish();

$sth = $dbh->prepare("SELECT * FROM zap2_domains");
$sth->execute;
       print $DOMAINS_FILE 'local-zone: zapret-info redirect', "\n";
	while (my $ips = $sth->fetchrow_hashref())
	{
	my $domain=$ips->{domain};
	my $domain_canonical=new URI("http://".$domain)->canonical();
	$domain_canonical =~ s/^http\:\/\///;
	$domain_canonical =~ s/\/$//;
	$domain_canonical =~ s/\.$//;
	next if($domain_canonical =~ /xn--/i);
	my $skip = 0;
	foreach my $dm (keys %masked_domains)
	{
		if($domain_canonical =~ /\.$dm$/)
		{
			$skip++;
			last;
		}
	}
	next if($skip);
	$logger->debug("Canonical domain: $domain_canonical");
       print $DOMAINS_FILE 'local-data: "', $domain_canonical,' A your-ip-add-here"', "\n";
}
$sth->finish();

close $DOMAINS_FILE;
close $DOMAINS_MASK_FILE;

$dbh->disconnect();

my $domains_file_hash=get_md5_sum($domains_file);
if($domains_file_hash ne $domains_file_hash_old)
{
	system("/usr/sbin/unbound-control", "reload");

	if($? != 0)
	{
		$logger->error("Can't reload or restart UNBOUND!");
		exit 1;
	}
                $logger->info("UNBOUND successfully reloaded!");

} else {
                $logger->info("Nothing change!");
                }

exit 0;

sub get_md5_sum
{
	my $file=shift;
	open(my $MFILE, $file) or return "";
	binmode($MFILE);
	my $hash=Digest::MD5->new->addfile(*$MFILE)->hexdigest;
	close($MFILE);
	return $hash;
}

