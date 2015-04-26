#!/usr/bin/perl

# The intend of this script is to submit usernames, passwords and IP addresses
# collected by kippo to DShield.org
# 
# Please configure your DShield UserID and AuthKey below
#
# To run this script, just pipe the log to it. e.g.
#   ./kippodshield.pl < kippo.log
# best done as part of an hourly log rotation script.
# For more about kippo, see https://code.google.com/p/kippo/
#
#   For help/suggestions/bug reports email hanlders@sans.edu 
# or use https://isc.sans.edu/contact.html .
#
# License: GPL 2.0

use strict;
use LWP::UserAgent;
use Digest::SHA;
use Digest::MD5;
use MIME::Base64 qw( encode_base64 decode_base64);

#
# Your userid and your authentication key can be found at
# https://isc.sans.edu/myinfo.html
#
# Both are listed below "Report Parameters". The userid is numeric.
# The authentication key is a base64 encoded random value and looks
# like: Ax1mrxCgRr2TsParadEvNA==  
#

my $DShieldUserID=948571171;
my $DShieldAuthKey='6a9b81e5fc58ba20c55922352ecfd36641f2d3a9';

# please adjust this file to where we can find our SSL CAs 
# the path here should work for Ubuntu and CentOS.
# Within this directory, you will typically find a file called
# ca-bundle.crt .

#my $SSLCAPath='/etc/ssl/certs';
my $SSLCAPath='/etc/pki/tls/certs';
my $SSLCAFile='/etc/pki/tls/certs/ca-bundle.crt';


my ($date, $time, $tz, $source, $user, $pw,$log,$lines);
$lines=0;
while (<STDIN>) {
    chomp();

#
# Sample log line. This is what we are trying to match.
#
# 2012-11-27 13:25:11+0000 [SSHService ssh-userauth on HoneyPotTransport,3794198,113.17.144.156] login attempt [root/marina] failed
#
    if ( /(2\d\d\d-\d\d-\d\d) (\d\d:\d\d:\d\d)([+-]\d{4}) [^,]+,\d+,([\d.]+)\] login attempt \[([^\/]+)\/([^\]]+)\]/ ) {
	$date=$1;
	$time=$2;
	$tz=$3;
	$source=$4;
	$user=$5;
	$pw=$6;
	$log.="$date\t$time\t$tz\t$source\t$user\t$pw\n";
	$lines++;
	if ( $lines>10000 ) {
	    submit();
	    $lines=0;
	    $log='';
	}
    }
}
if ( $lines>0 ) {
submit();
}

#
# This function submits the log to our web services API
#

sub submit() {
    my $ua = LWP::UserAgent->new;
    my $nonce = Digest::SHA::hmac_sha256(rand(),$$);

# trying to avoid sending the authentication key in the "clear" but not wanting to
# deal with a full digest like exchange. Using a fixed nonce to mix up the limited
# userid. 

    my $nonce=decode_base64('ElWO1arph+Jifqme6eXD8Uj+QTAmijAWxX1msbJzXDM=');
    my $hash= Digest::SHA::hmac_sha256_base64(decode_base64($DShieldAuthKey),$nonce.$DShieldUserID);
    $hash=$hash."=" x (length($hash)%3);
    my $nonce=encode_base64($nonce);
    chomp($nonce);
    my $header= "credentials=$hash nonce=$nonce userid=$DShieldUserID";
    $ua->timeout(10);
    $ua->ssl_opts(verify_hostname=>1);
    $ua->ssl_opts(SSL_ca_file=>$SSLCAFile);
    print "Submitting Log\nLines: $lines Bytes: ".length($log)."\n";

# This is our REST API end point. We use the custom header "X-ISC-Authorization" for authentication
    my $req=new HTTP::Request('PUT','https://secure.dshield.org/api/file/sshlog');
    $req->header('X-ISC-Authorization',$header);
    $req->header('Content-Type','text/plain');
    $req->header('Content-Length',length($log));
    $req->content($log);
    my $result=$ua->request($req);
    if ($result->is_success) {
	my $return=$result->decoded_content; 
        $return=~/<bytes>(\d+)<\/bytes>/;
	my $receivedbytes=$1;
	if ( $receivedbytes !=length($log) ) {
	    print "\nERROR: Size Mismatch\n";
	} else {
            print "Size OK ";
        }
        $return=~/<sha1checksum>([^<]+)<\/sha1checksum>/;
	my $receivedsha1=$1;
	if ( $receivedsha1 ne Digest::SHA::sha1_hex($log) ) {
	    print "\nERROR: SHA1 Mismatch $receivedsha1 ".Digest::SHA::sha1_hex($log)."\n";
	} else {
            print "SHA1 OK ";
        }

        $return=~/<md5checksum>([^<]+)<\/md5checksum>/;
	my $receivedmd5=$1;
	if ( $receivedmd5 ne Digest::MD5::md5_hex($log) ) {
print "\nERROR: MD5 Mismatch $receivedmd5 ".Digest::MD5::md5_hex($log)."\n";
	} else {
	    print "MD5 OK\n";
        }
    }
    else {
	die $result->status_line;
    } 
    print "---\n";
}
