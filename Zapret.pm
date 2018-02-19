package Zapret;

require Exporter;

@ISA = qw/Exporter/;
@EXPORT = qw//;

use utf8;
use strict;
use SOAP::Lite;
use MIME::Base64;

my $VERSION='0.01';

BEGIN {
	sub SOAP::Transport::HTTP::Client::get_basic_credentials {
        return 'LoginNewUrl' => 'PasswdNewUrl';
        }
}

sub new
{
	my $class=shift;
	my $URL=shift || die("URL not defined");
	my $self={
		service => SOAP::Lite->service($URL),
		      
	};
	bless $self,$class;
	return $self;
}

sub getDumpDelta
{
	my $this=shift;
	my $deltaId=shift;
	return $this->{service}->getDumpDelta($deltaId);
}

sub getResult
{
	my $this=shift;
	my $code=shift;
	return $this->{service}->getResult($code);
}

sub getDumpDeltaList
{
        my $this=shift;
        my $actualDate=shift;
        my $resultCode=shift;
        return $this->{service}->getDumpDeltaList($actualDate);

}

1;
