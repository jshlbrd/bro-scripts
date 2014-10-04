# Tinder data is sent unencrypted and can easily be seen and extracted from network traffic
# Josh Liburdi 2014

module PolicyViolation;

export {

  redef enum Notice::Type += {
    Tinder
  };
}

global extract_tinder_image: set[string];

const tinder_extract_images: bool = F &redef;

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
{
if ( c$http?$method && c$http$method != "GET" ) return;
if ( name == "USER-AGENT" && "Tinder" !in value ) return;
if ( name == "HOST" && value != "images.gotinder.com" ) return;

NOTICE([$note=Tinder,
        $conn=c,
        $msg=fmt("%s appears to be using Tinder",c$id$orig_h),
        $identifier=cat(c$id$orig_h)]);

if ( tinder_extract_images == T )
  if ( c$uid !in extract_tinder_image )
    add extract_tinder_image[c$uid];
}

event file_new(f: fa_file) &priority=3
{
if ( |extract_tinder_image| == 0 ) return;
if ( f$info$mime_type != "image/jpeg" ) return;

for ( cid in f$conns )
  if ( f$conns[cid]$uid in extract_tinder_image )
    {
    local fname = fmt("Tinder-%s-%s", f$conns[cid]$id$orig_h, f$id);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    delete extract_tinder_image[f$conns[cid]$uid];
    }
}

event connection_state_remove(c: connection)
{
if ( |extract_tinder_image| == 0 ) return;
if ( c$uid in extract_tinder_image )
  delete extract_tinder_image[c$uid];
}
