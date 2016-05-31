#!/usr/bin/env perl
use Modern::Perl;

use lib ".";
use File::KeePass::Open qw(open_keepass);
use File::KeePass::Diff qw(diff_keepass print_entry);
use Text::Table;
use Data::Dumper;

my ($source1_path, $source2_path, $print_password) = @ARGV;

die "Usage: $0 keepassdb1.kdb keepassdb2.kdb [print_password]" unless $source1_path and $source2_path and ($source1_path ne $source2_path);

my $source1 = open_keepass($source1_path);
my $source2 = open_keepass($source2_path);
$| = 1;
my ($common, $only1, $only2, $differ) = diff_keepass($source1, $source1_path, $source2, $source2_path);

unless (@$only1 or @$only2 or @$differ) {
  say "$source1_path and $source2_path are identical.";
  exit;
}

if (@$only1) {
  say "Only in $source1_path:";
  for my $entry (@$only1) {
    say "------------------------------------------";
    print_entry($entry);
    say '-';
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
    say '-';
  }
}
else {
  say "There are no entries in $source2_path that are not in $source1_path.";
}
say "------------------------------------------\n";

if (@$differ) {
  my $table = Text::Table->new('', $source1_path, $source2_path);
  $table->add('', ('=' x length($source1_path)), ('=' x length($source2_path)));
  for my $thrice (@$differ) {
    my ($entry1, $entry2, $difference) = @$thrice;
    for my $field (@File::KeePass::Diff::default_fields) {
      next if $entry1->{$field} !~ /\S/ and $entry2->{$field} !~ /\S/;
      my $label = ($entry1->{$field} eq $entry2->{$field}) ? $field : "*$field";
      unless ($print_password and $field eq 'password') {
        $table->add($label, $entry1->{$field}, $entry2->{$field});
      }
      else {
        $table->add($label);
      }
    }
    $table->add('-');
  }
  print $table;
}
else {
  say "No entries differ between them."
}

