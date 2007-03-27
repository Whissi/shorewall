#
# Shorewall-pl 3.9 -- /usr/share/shorewall-pl/Shorewall/Common.pm
#
#     This program is under GPL [http://www.gnu.org/copyleft/gpl.htm]
#
#     (c) 2007 - Tom Eastep (teastep@shorewall.net)
#
#       Complete documentation is available at http://shorewall.net
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of Version 2 of the GNU General Public License
#       as published by the Free Software Foundation.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
#
#
package Shorewall::Common;
require Exporter;
use File::Basename;
use File::Temp qw/ tempfile tempdir /;
use Cwd 'abs_path';

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(ALLIPv4

		 warning_message 
		 fatal_error
		 split_line
		 create_temp_object
		 finalize_object
		 emit
		 emitj
		 emit_unindented
		 emit_as_is
		 save_progress_message
		 save_progress_message_short
		 progress_message
		 progress_message2
		 progress_message3
		 push_indent
		 pop_indent
		 copy
		 copy1
		 create_temp_aux_config
		 finalize_aux_config

		 @allipv4
		 @rfc1918_networks
		 $line
		 $command
		 $doing
		 $done
		 );
our @EXPORT_OK = ();
our @VERSION = 1.00;

#
# Some IPv4 useful stuff
#
our @allipv4 = ( '0.0.0.0/0' );

use constant { ALLIPv4 => '0.0.0.0/0' };

our @rfc1918_networks = ( "10.0.0.0/24", "172.16.0.0/12", "192.168.0.0/16" );

our $line = '';          # Current config file line

our ( $command, $doing, $done ) = qw/ compile Compiling Compiled/; #describe the current command, it's present progressive, and it's completion.

my $object = 0;          # Object file Handle Reference
my $lastlineblank = 0;   # Avoid extra blank lines in the output
my $indent        = '';
my ( $dir, $file );      # Object's Directory and File
my $tempfile;            # Temporary File Name

#
# Issue a Warning Message
#
sub warning_message 
{
    print STDERR "   WARNING: @_\n";
}

#
# Fatal Error
#
sub fatal_error
{
    print STDERR "   ERROR: @_\n";
    die;
}

#
# Pre-process a line from a configuration file.
#
#    chomp it.
#    compress out redundent white space.
#    ensure that it has an appropriate number of columns.
#    supply '-' in omitted trailing columns.
#
sub split_line( $$ ) {
    my ( $columns, $description ) = @_;

    chomp $line;

    $line =~ s/\s+/ /g;

    my @line = split /\s+/, $line;

    return @line if $line[0] eq 'COMMENT';

    fatal_error "Invalid $description entry: $line" if @line > $columns;

    push @line, '-' while @line < $columns;

    @line;
}

sub create_temp_object( $ ) {
    my $objectfile = $_[0];
    my $suffix;

    eval {
	( $file, $dir, $suffix ) = fileparse( $objectfile );
	$dir = abs_path $dir;
	fatal_error "Directory $dir does not exist" unless -d $dir;
	fatal_error "$dir is a Symbolic Link" if -l $dir;
	fatal_error "$objectfile is a Directory" if -d $objectfile;
	fatal_error "$dir is a Symbolic Link" if -l $objectfile;
	fatal_error "$objectfile exists and is not a compiled script" if -e _ && ! -x _;
	( $object, $tempfile ) = tempfile ( 'tempfileXXXX' , DIR => $dir );
    };

    die if $@;

    $file = "$file.$suffix" if $suffix;
    $dir .= '/' unless substr( $dir, -1, 1 ) eq '/';
    $file = $dir . $file;

}

sub finalize_object() {
    close $object;
    $object = 0;
    rename $tempfile, $file or fatal_error "Cannot Rename $tempfile to $file: $!";
    chmod 0700, $file;
}

#
# Write the argument to the object file (if any) with the current indentation.
# 
# Replaces leading spaces with tabs as appropriate and suppresses consecutive blank lines.
#
sub emit ( $ ) {
    if ( $object ) {
	#
	# 'compile' as opposed to 'check'
	#
	my $line = $_[0];

	unless ( $line =~ /^\s*$/ ) {
	    $line =~ s/^\n// if $lastlineblank;
	    $line =~ s/^/$indent/gm if $indent;
	    1 while $line =~ s/^        /\t/m;
	    print $object "$line\n";
	    $lastlineblank = ( substr( $line, -1, 1 ) eq "\n" );
	} else {
	    print $object "\n" unless $lastlineblank;
	    $lastlineblank = 1;
	}
    }
}

#
# Jacket for emit() that accepts an indefinite number of arguments; each argument will be emitted as a separate line
#
sub emitj {
    if ( $object ) {
	#
	# 'compile' as opposed to 'check'
	#
	for ( @_ ) {
	    unless ( /^\s*$/ ) {
		my $line = $_;
		$line =~ s/^\n// if $lastlineblank;
		$line =~ s/^/$indent/gm if $indent;
		1 while $line =~ s/^        /\t/;
		print $object "$line\n";
		$lastlineblank = ( substr( $line, -1, 1 ) eq "\n" );
	    } else {
		print $object "\n" unless $lastlineblank;
		$lastlineblank = 1;
	    }
	}
    }
}


#
# Write passed message to the object with no indentation.
#

sub emit_unindented( $ ) {
    print $object "$_[0]\n" if $object;
}

#
# Write passed message to the object with no indentation or added newline.
#

sub emit_as_is( $ ) {
    print $object "$_[0]" if $object;
}

#
# Write a progress_message2 command to the output file.
#
sub save_progress_message( $ ) {
    emit "\nprogress_message2 @_\n" if $object;
}

sub save_progress_message_short( $ ) {
    emit "progress_message $_[0]" if $object;
}

sub progress_message {
    if ( $ENV{VERBOSE} > 1 ) {
	my $ts = '';
	$ts = ( localtime ) . ' ' if $ENV{TIMESTAMP};
	print "${ts}@_\n";
    }
}

sub timestamp() {
    my ($sec, $min, $hr) = ( localtime ) [0,1,2];
    printf '%02d:%02d:%02d ', $hr, $min, $sec;
}

sub progress_message2 {
    if ( $ENV{VERBOSE} > 0 ) {
	timestamp if $ENV{TIMESTAMP};
	print "@_\n";
    }
}

sub progress_message3 {
    if ( $ENV{VERBOSE} >= 0 ) {
	timestamp if $ENV{TIMESTAMP};
	print "@_\n";
    }
}

#
# Push/Pop Indent
#
sub push_indent() {
    $indent = "$indent    ";
}

sub pop_indent() {
    $indent = substr( $indent , 0 , ( length $indent ) - 4 );
}

#
# Functions for copying files into the object
#
sub copy( $ ) {
    if ( $object ) {
	my $file = $_[0];

	open IF , $file or fatal_error "Unable to open $file: $!";

	while ( my $line = <IF> ) {
	    $line =~ s/^/$indent/ if $indent;
	    print $object $line;
	}

	close IF;
    }
}

sub copy1( $ ) {
    if ( $object ) {
	my $file = $_[0];

	open IF , $file or fatal_error "Unable to open $file: $!";

	my $do_indent = 1;

	while ( my $line = <IF> ) {
	    if ( $line =~ /^\s+$/ ) {
		print $object "\n";
		$do_indent = 1;
		next;
	    }

	    $line =~ s/^/$indent/ if $indent && $do_indent;
	    print $object $line;
	    $do_indent = ! ( $line =~ /\\$/ );
	}

	close IF;
    }
}

sub create_temp_aux_config() {
    eval {
	( $object, $tempfile ) = tempfile ( 'tempfileXXXX' , DIR => $dir );
    };

    die if $@;

}

sub finalize_aux_config() {
    close $object;
    $object = 0;
    rename $tempfile, "$file.conf" or fatal_error "Cannot Rename $tempfile to $file.conf: $!";

    progress_message3 "Shorewall configuration compiled to $file";
}

END {
    if ( $object ) {
	close $object;
	unlink $tempfile;
    }

    system "rm -rf $ENV{TMP_DIR}" if $ENV{TMP_DIR};
}

1;
