# We dont want or need any of the implicit rules, and having them around
# makes the debugging output horrendously long and painful to read.

# Get rid of most of the implicit rules by clearing the .SUFFIXES target
.SUFFIXES:
# Get rid of the auto-checkout from old version control systems rules
%: %,v
%: RCS/%,v
%: RCS/%
%: s.%
%: SCCS/s.%
