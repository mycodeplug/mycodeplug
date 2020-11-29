# Architecture

## Goals

* Wide compatibility between input and output formats
* Share configurations at any level of granularity
* Reduce cognitive load
  * Don't go to 2 different places to define dependent data (ex: talkgroups and channels should be in the same UI)
  * Inherit settings from "parent" channels
  * Automatically expand static talkgroups into channels
  * Automatically create scanlists, etc
  
# Design

## Channel

A `Channel` is the most fundamental element of codeplug data defining
the `frequency`, `offset`, `tone`/`cc`, `mode`, and `name`.

All channels have a UUID as their primary identifier as well as a "parent" ID. Any settings that are not explicitly
set on the channel are derived from the parent. The parent may also have a parent, and so on. To avoid ref loops,
an error is raised if applying settings from a parent does not yield a change in the current channel.

To better handle imports, a channel may have a `source` and `source_key`. Typically a source would be a URL
to a CSV file or other custom import. The source_key is the part of the channel which uniquely identifies it
within the source. For repeaterbook, this would be the (State ID, Rptr ID) pair that uniquely identifies a
channel from repeaterbook export. For other CSV files, the key might have to be (Frequency, Call) unless some
other identifier is available.

When importing/copying a channel, the parent link is severed and all settings are collapsed and copied
into the new channel.

When linking a channel, the new channel only has a parent link and all settings are empty until they
are overridden.

A channel may contain radio-specific settings that can be defined as JSON blob to be interpreted by the
export driver.

### `AnalogChannel`

Defines tone in/out and any other analog-only settings

### `DMRChannel`

Talkgroups: a list of (talkgroup, timeslot) pairs

A TG List ("RX List") is a list of (talkgroup, timeslot) pairs. It is created implicitly when
defining the DMRChannel, however it can be linked and shared with other channels. It
can also define a "parent" list to make modifications from an upstream list simpler.
(see Zone for more on the inherited list structure)

When generating a codeplug for most commonly-available DMR radios, 1 channel will be made per talkgroup
in the list. An option determines whether each generated channel includes an RX list
for all other talkgroups on that repeater/timeslot combination.

## Zone

A `Zone` is a container for channels. A zone may contain other zones. A zone may be
imported from another codeplug.

Similar to channels, a zone may be linked to a parent zone. This is different that
a zone being contained within a zone.

A zone is defined by its `name`, `parent`, default channel, and a UUID. The list of
channels in a zone is given by (channel_uuid, ["present"/"absent"]). The final
list of channels for a zone is found by discovering the root ancestor and building
the channel list iteratively, adding or removing channels until all zones have been
processed. This allows a linked zone to add, remove, or modify channels while
maintaining a minimal diff from the upstream zone/channel.

A scanlist is basically a zone that doesn't get generated as a zone in the codeplug,
but for UI and database purposes it is identical: a list of channels.

## RadioConfig

Callsign, DMR ID, startup message, various settings. It's going to differ widely from
radio to radio. Allow JSON specified options that can be read directly by the different
export drivers. Also exposes a "parent" field to inherit options.

## Codeplug

A `Codeplug` is a container for zones and RadioConfig. Like all other objects, it
too may have a "parent" field to allow inheritance of zones and settings.

A codeplug is defined by its `name`, `parent`, default channel, `config_uuid`, and a UUID. The
list of zones in a channel is given by (zone_uuid, ["present"/"absent"]). The
final list of zones is constructed similarly to the zone channel list.

Like the zone, the default channel exists to fill in any channels settings that
are not applied by the channel or zone default channel. This makes it easier to cascade
common settings throughout the codeplug and avoid the kind of rote editing that
is common with traditional CPS or spreadsheet-based modifications.

# UI

Since most data can be inherited in this model, it is important to use
a color coding scheme to show the true source of each piece of data.
Furthermore, it should be obvious where each field and each piece of data
is inherited from and it should be simple to break that link on a
field-by-field basis.

When "saving" a codeplug, the flattened form should be saved in addition to
the structured version. This will allow users to easily see what has changed
in any linked data and selectively retain changes in their existing codeplug.

## Layout

A 2 column layout is used with Zones and Scanlists in the left column and
channels in the right column. The right column is sort of a spreadsheet with
customizable headers for quick editing. Double clicking on a channel opens
the channel editor modal. On a mobile device, each column fills 1 portrait
screen and animates to slide between them.

Double clicking a zone opens the default channel for the zone. The codeplug default
channel is accessed via a menu drop-down.

At the bottom of each column a `[+]` button allows the addition of a zone or
channel from "new", "template", "import". Selecting template allows the user
to search for an existing zone or channel in the system. Selecting import
allows the user to upload a csv or other supported format.
