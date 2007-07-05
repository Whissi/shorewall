#
# Shorewall-perl 4.0 -- /usr/share/shorewall-perl/Shorewall/Common.pm
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
#   This is the lowes level Shorewall module. It provides very basic 
#   services such as creation of temporary 'object' files, writing
#   into those files (emitters) and finalizing those files (renaming 
#   them to their final name and setting their mode appropriately).
#
package Shorewall::Common;
require Exporter;
use File::Basename;
use File::Temp qw/ tempfile tempdir /;
use Cwd 'abs_path';

use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		 create_temp_object
		 finalize_object
		 emit
		 emitj
		 emit_unindented
		 save_progress_message
		 save_progress_message_short
		 set_timestamp
		 set_verbose
		 progress_message
		 progress_message2
		 progress_message3
		 push_indent
		 pop_indent
		 copy
		 copy1
		 create_temp_aux_config
		 finalize_aux_config

		 $line
		 $command
		 $doing
		 $done
		 $verbose
		 );
our @EXPORT_OK = qw( $timestamp initialize );
our $VERSION = 4.00;

our $line;
our ($command, $doing, $done );
our $verbose;
our $timestamp;
our $object;
our $lastlineblank;
our $indent;
our ( $dir, $file );      # Object's Directory and File
our $tempfile;            # Temporary File Name

#
# Initialize globals -- we take this novel approach to globals initialization to allow
#                       the compiler to run multiple times in the same process. The
#                       initialize() function does globals initialization for this
#                       module and is called from an INIT block below. The function is
#                       also called by Shorewall::Compiler::compiler at the beginning of
#                       the second and subsequent calls to that function. 
#

sub initialize() {
    $line = '';          # Current config file line

    ( $command, $doing, $done ) = qw/ compile Compiling Compiled/; #describe the current command, it's present progressive, and it's completion.

    $verbose = 0;              # Verbosity setting. 0 = almost silent, 1 = major progress messages only, 2 = all progress messages (very noisy)
    $timestamp = '';           # If true, we are to timestamp each progress message
    $object = 0;               # Object (script) file Handle Reference
    $lastlineblank = 0;        # Avoid extra blank lines in the output
    $indent        = '';       # Current indentation
    ( $dir, $file ) = ('',''); # Object's Directory and File
    $tempfile = '';            # Temporary File Name
}

INIT {
    initialize;
}

#
# Fatal Error
#
sub fatal_error
{
    die "   ERROR: @_\n";
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
	my $line = $_[0]; # This copy is necessary because the actual arguments are almost always read-only.

	unless ( $line =~ /^\s*$/ ) {
	    $line =~ s/^\n// if $lastlineblank;
	    $line =~ s/^/$indent/gm if $indent;
	    $line =~ s/        /\t/gm;
	    print $object "$line\n";
	    $lastlineblank = ( substr( $line, -1, 1 ) eq "\n" );
	} else {
	    print $object "\n" unless $lastlineblank;
	    $lastlineblank = 1;
	}
    }
}

#
# Version of emit() that accepts an indefinite number of scalar arguments; each argument will be emitted as a separate line
#
sub emitj {
    if ( $object ) {
	#
	# 'compile' as opposed to 'check'
	#
	for ( @_ ) {
	    unless ( /^\s*$/ ) {
		my $line = $_; # This copy is necessary because the actual arguments are almost always read-only.
		$line =~ s/^\n// if $lastlineblank;
		$line =~ s/^/$indent/gm if $indent;
		$line =~ s/        /\t/gm;
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
# Write passed message to the object with newline but no indentation.
#

sub emit_unindented( $ ) {
    print $object "$_[0]\n" if $object;
}

#
# Write a progress_message2 command with surrounding blank lines to the output file.
#
sub save_progress_message( $ ) {
    emit "\nprogress_message2 @_\n" if $object;
}

#
# Write a progress_message command to the output file.
#
sub save_progress_message_short( $ ) {
    emit "progress_message $_[0]" if $object;
}

#
# Set $timestamp
# 
sub set_timestamp( $ ) {
    $timestamp = shift;
}

#
# Set $verbose
# 
sub set_verbose( $ ) {
    $verbose = shift;
}

#
# Print the current TOD to STDOUT.
# 
sub timestamp() {
    my ($sec, $min, $hr) = ( localtime ) [0,1,2];
    printf '%02d:%02d:%02d ', $hr, $min, $sec;
}

#
# Write a message if $verbose >= 2
#
sub progress_message {
    if ( $verbose > 1 ) {
	timestamp if $timestamp;
	my $line = join( ' ', @_ );
	$line =~ s/\s+/ /g;
	print "$line\n";
    }
}

#
# Write a message if $verbose >= 1
#
sub progress_message2 {
    if ( $verbose > 0 ) {
	timestamp if $timestamp;
	print "@_\n";
    }
}

#
# Write a message if $verbose >= 0
#
sub progress_message3 {
    if ( $verbose >= 0 ) {
	timestamp if $timestamp;
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

	while ( <IF> ) {
	    s/^/$indent/ if $indent;
	    print $object $_;
	}

	close IF;
    }
}

#
# This one handles line continuation.

sub copy1( $ ) {
    if ( $object ) {
	my $file = $_[0];

	open IF , $file or fatal_error "Unable to open $file: $!";

	my $do_indent = 1;

	while ( <IF> ) {
	    if ( /^\s*$/ ) {
		print $object "\n";
		$do_indent = 1;
		next;
	    }

	    s/^/$indent/ if $indent && $do_indent;
	    print $object $_;
	    $do_indent = ! ( /\\$/ );
	}

	close IF;
    }
}

#
# Create the temporary object file -- the passed file name is the name of the final file.
# We create a temporary file in the same directory so that we can use rename to finalize it.
#
sub create_temp_object( $ ) {
    my $objectfile = $_[0];
    my $suffix;

    eval {
	( $file, $dir, $suffix ) = fileparse( $objectfile );
    };

    die if $@;

    fatal_error "Directory $dir does not exist"  unless -d $dir;
    fatal_error "Directory $dir is not writable" unless -w _;
    fatal_error "$dir is a Symbolic Link"        if -l $dir;
    fatal_error "$objectfile is a Directory"     if -d $objectfile;
    fatal_error "$dir is a Symbolic Link"        if -l $objectfile;
    fatal_error "$objectfile exists and is not a compiled script" if -e _ && ! -x _;

    eval {
	$dir = abs_path $dir;
	( $object, $tempfile ) = tempfile ( 'tempfileXXXX' , DIR => $dir );
    };

    fatal_error "Unable to create temporary file in directory $dir" if $@;

    $file = "$file.$suffix" if $suffix;
    $dir .= '/' unless substr( $dir, -1, 1 ) eq '/';
    $file = $dir . $file;

}

#
# Finalize the object file
#
sub finalize_object( $ ) {
    my $export = $_[0];
    close $object;
    $object = 0;
    rename $tempfile, $file or fatal_error "Cannot Rename $tempfile to $file: $!";
    chmod 0700, $file or fatal_error "Cannot secure $file for execute access";
    progress_message3 "Shorewall configuration compiled to $file" unless $export;
}

#
# Create the temporary aux config file.
#
sub create_temp_aux_config() {
    eval {
	( $object, $tempfile ) = tempfile ( 'tempfileXXXX' , DIR => $dir );
    };

    die if $@;

}

#
# Finalize the aux config file.
#
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
}

1;
