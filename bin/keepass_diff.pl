#!/usr/bin/env perl
use Modern::Perl;

use lib ".";
use File::KeePass::Open qw(open_keepass);
use File::KeePass::Diff qw(diff_keepass print_entry);
use Data::Dumper;

my ($source1_path, $source2_path, $print_password) = @ARGV;

die "Usage: $0 keepassdb1.kdb keepassdb2.kdb [print_password]" unless $source1_path and $source2_path and ($source1_path ne $source2_path);

my $source1 = open_keepass($source1_path);
my $source2 = open_keepass($source2_path);
$| = 1;
my ($common, $only1, $only2, $differ) = diff_keepass($source1, $source1_path, $source2, $source2_path);
if (@$only1) {
  say "Only in $source1_path:";
  for my $entry (@$only1) {
    say "------------------------------------------";
    print_entry($entry);
  }
}
else {
  say "There are no entries in $source1_path that are not in $source2_path.";
}
say "------------------------------------------\n";

if (@$only2) {
  say "Only in $source2_path:";
  for my $entry (@$only2) {
    print_entry($entry);
  }
}
else {
  say "There are no entries in $source2_path that are not in $source1_path.";
}
say "------------------------------------------\n";
if (@$differ) {
  for my $thrice (@$differ) {
    my ($entry1, $entry2, $difference) = @$thrice;
    say "Entries differ in ", (join ', ', keys %$difference), ':';
    say "${source1_path}'s version:";
    say "------------------------------------------";
    print_entry($entry1, undef, undef, $print_password);
    say "${source2_path}'s version:";
    say "------------------------------------------";
    print_entry($entry2, undef, undef, $print_password);
  }
}
else {
  say "No entries differ between them."
}

