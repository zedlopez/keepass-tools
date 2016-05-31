#!/usr/bin/env perl
use strict;
use warnings;
use v5.10;

use File::KeePass;
use Data::Dumper;
use Term::ReadLine;
use Term::ReadPassword;
use File::Temp qw(tempfile);
use File::Copy;
use File::Basename;
$Term::ReadPassword::USE_STARS=1;
$| = 1;

my ($source1_name, $source2_name, $output_name) = @ARGV;

die "Usage: $0 keepassdb1.kdb keepassdb2.kdb newkeepassdb.kdb" unless $source1_name and $source2_name and $output_name and $source1_name ne $source2_name and $source1_name ne $output_name and $source2_name ne $output_name;

die "can't read $source1_name" unless -r $source1_name;
die "can't read $source2_name" unless -r $source2_name;
die "$output_name already exists" if -e $output_name;

my ($tmpfh, $tmpfilename) = tempfile();

sub open_keepass {
  my $filename = shift;
  my $pw = read_password("Enter password for $filename: ");
  my $keepass = File::KeePass->new;
  eval { $keepass->load_db($filename, $pw) };
  die "Couldn't open $filename with given password" if $@;
  return $keepass;
}

my $source1 = open_keepass($source1_name);
#print Dumper($source1->header);
# print $source1->dump_groups;
# print $source1->is_locked ? 'locked' : 'unlocked';
# $source1->unlock;
# print $source1->is_locked ? 'locked' : 'unlocked';
# print $source1->dump_groups;
my $source2 = open_keepass($source2_name);

my $source1_basename = basename($source1);
my $source2_basename = basename($source2);


$source1->unlock;
$source2->unlock;

my $merged_password = read_password("Enter password for $output_name: ");
# my $confirmed_merged_password = read_password("Confirm password for $output_name: ");

# die "Passwords didn't match" unless $merged_password eq $confirmed_merged_password;



sub build_entry_hash {
  my $keepass = shift;
  my @group_list = $keepass->find_groups({'title !' => 'Backup'});
  my %entries;
  my %groups;
  my %group_entries;
  for my $group (@group_list) {
      $groups{$group->{id}} = $group;
      #      say $group->{title};
#      print "group:\n", Dumper($group);
      my @entry_list = $keepass->find_entries({group_id => $group->{id}});
#      print "entry list:\n", Dumper(\@entry_list);
      for my $entry (@{$group->{entries}}) {
          next if $entry->{title} eq 'Meta-Info';
          $entries{$entry->{id}} = $entry;
          $group_entries{$entry->{id}} = $group->{id};
      }
  }
  return (\%entries, \%groups);
}



my ($entries1, $groups1) = build_entry_hash($source1);
my ($entries2, $groups2) = build_entry_hash($source2);

sub strip {
  my $str = shift;
  $str =~ s/^\s+//;
  $str =~ s/\s+$//;
  $str =~ s/\r\n/\n/g;
  return $str;
}

sub different {
  my ($entry1, $entry2) = @_;
  my %result;
  for my $field (qw(title url username password created modified binary)) {
      next if !defined $entry1->{$field} and !defined $entry2->{$field};
      if ((!defined $entry1->{$field} and defined $entry2->{$field}) or (defined $entry1->{$field} and !defined $entry2->{$field})) {
          $result{$field} = 1;
          next;
      }
    $result{$field} = 1 if $entry1->{$field} ne $entry2->{$field};
  }
  
  my $comment1 = strip($entry1->{comment});
  my $comment2 = strip($entry2->{comment});
  return \%result
}

my $merged = File::KeePass->new;
my $merged_group = $merged->add_group({title => 'Passwords'});
my $term = Term::ReadLine->new('keepass_merge');

while (my ($id,$entry1) = each %$entries1) {
  next if $id eq '00000000000000000000000000000000';
  my $title = $entry1->{title};
  my $username = $entry1->{username};
  my ($entry2, $differences);
  if (exists $entries2->{$id}) {
    $entry2 = $entries2->{$id};
    $differences = different($entry1, $entry2);
  }
  # if it exists only in source1 or there's no difference or the only difference is modified time
  if (!defined $differences or ((scalar keys %$differences == 0) or ((scalar keys %$differences == 1 and exists $differences->{modified})))) {
    $merged->add_entry({ %{$entry1}, group => $merged_group});
    next;
  }
  $title .= "/".$entry2->{title} if $entry1->{title} ne $entry2->{title};
  $username .= "/".$entry2->{username} if $entry1->{username} ne $entry2->{username};
  my ($newer, $older, $newer_name, $older_name) = ($entry2, $entry1, $source2_name, $source1_name);
  if ($entry1->{modified} gt $entry2->{modified}) {
    ($newer, $older, $newer_name, $older_name) = ($entry1, $entry2, $source1_name, $source2_name);
  }
  my $length = (length $newer_name > length $older_name) ? length $newer_name : length  $older_name;
  say "For username: $username , title: $title:";
  for my $field (qw(password binary)) {
    say join '', ucfirst($field), "s differ." if exists $differences->{$field};
    say join '', $source1_basename, ': ', $entry1->{$field};
    say join '', $source2_basename, ': ', $entry2->{$field};
  }
  for my $field (qw(title url username created comment bindesc modified)) {
    if (exists $differences->{$field}) {
      say sprintf "% ${length}s's %s: %s", $older_name, ucfirst($field), $older->{$field};
      say sprintf "% ${length}s's %s: %s", $newer_name, ucfirst($field), $newer->{$field};
    }
  }
  my $input;
  while (defined ($input = $term->readline("Keep values for $newer_name (y/n)? "))) {
    say "|$input|";
    last if $input =~ /^\s*[yn]/i;
  }

  my $keeper = (($input =~ /^y/i) ? $newer : $older);
  $merged->add_entry({ %{$keeper}, group => $merged_group});

}
while (my ($id,$entry2) = each %$entries2) {
  next if $id eq '00000000000000000000000000000000';
  my $title = $entry2->{title};
  unless (exists $entries1->{$id}) {
    #    say "Entry $id ($title) exists only in $source2_name.";
    $merged->add_entry({ %{$entry2}, group => $merged_group});
  }
}

$merged->save_db($tmpfilename, $merged_password);
open my $fh, '>', $output_name or die "Couldn't open $output_name for write: $!";
copy($tmpfilename, $fh);



