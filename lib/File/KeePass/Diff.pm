package File::KeePass::Diff;
use Modern::Perl;
use Exporter::Easy (OK => ['diff_keepass', 'print_entry']);
use File::KeePass;
use Data::Dumper;

our @default_fields = (qw(title url username password comment));

sub build_entry_hash {
  my $keepass = shift;
  my @group_list = $keepass->find_groups({'title !' => 'Backup'});
  my %entries;
  my %groups;
  my %group_entries;
  for my $group (@group_list) {
    $groups{$group->{id}} = $group;
    my @entry_list = $keepass->find_entries({group_id => $group->{id}});
    for my $entry (@{$group->{entries}}) {
      next if $entry->{title} eq 'Meta-Info';
      $entries{$entry->{id}} = $entry;
      $group_entries{$entry->{id}} = $group->{id};
    }
  }
  return (\%entries, \%groups);
}


sub strip {
  my $str = shift;
  $str =~ s/^\s+//;
  $str =~ s/\s+$//;
  $str =~ s/\r\n/\n/g;
  return $str;
}

sub descriptor {
  my ($entry1, $entry2) = @_;
  my %entry1 = %$entry1;
  my %entry2 = %$entry2;
  for my $field (qw(title url username password created modified binary)) {
    $entry1{$field} //= "[undefined $field]";
    $entry2{$field} //= "[undefined $field]";
  }
  return $entry1{title} if $entry1{title} eq $entry2{title};
  return join ' / ', $entry1{title}, $entry2{title};
}

sub different {
  my ($entry1, $entry2, @fields) = @_;
  my %result = ();
  for my $field (@fields) {
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

sub diff_keepass {
  my ($source1, $source1_path, $source2, $source2_path, $sensitive, $insensitive) = @_;
  my @fields = get_fields($sensitive, $insensitive);
  $source1->unlock;
  $source2->unlock;

  my ($entries1, $groups1) = build_entry_hash($source1);
  my ($entries2, $groups2) = build_entry_hash($source2);

  my (@only_in_source1, @only_in_source2, @common, @differ);

  while (my ($id,$entry1) = each %$entries1) {
    #    $entry1->{id} = unpack "i", $entry1->{id};
    next unless $id;

    my ($entry2, $differences);
    unless (exists $entries2->{$id}) {
      push @only_in_source1, $entry1;
      next;
    }
    $entry2 = $entries2->{$id};
    $differences = different($entry1, $entry2, @fields);
    if (!%$differences or (scalar keys %$differences == 1 and exists $differences->{modified})) {
      push @common, $entry1;
    } else {
      push @differ, [$entry1, $entry2, $differences];
    }
  }
  while (my ($id,$entry2) = each %$entries2) {
    #    $entry2->{id} = unpack "i", $entry2->{id};
    next unless $id;
    push @only_in_source2, $entry2 unless exists $entries1->{$id};
  }
  return (\@common, \@only_in_source1, \@only_in_source2, \@differ);
}

sub get_fields {
  my ($sensitive, $insensitive) = @_;
  my @fields = @default_fields;
  if (defined $sensitive and @$sensitive) {
    push @fields, $_ for @$sensitive;
  }
  my %h;
  @h{@fields} = (1);
  if (defined $insensitive and @$insensitive) {
    for my $field (@$insensitive) {
      delete $h{$field} if exists $h{$field};
    }
  }
  return keys %h;
}

sub print_entry {
  my ($entry, $sensitive, $insensitive, $print_password, $ignore_blank) = @_;
  my @fields = get_fields($sensitive, $insensitive);
  $print_password //= 0;
  $ignore_blank //= 1;
  for my $field (@fields) {
    next if $field eq 'password' and !$print_password;
    next if $ignore_blank and $field !~ /\S/;
    say join ': ', ucfirst($field), ($entry->{$field} // "[undefined]");
  }
}

1;
