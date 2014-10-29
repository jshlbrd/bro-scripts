# Simple logging of Reddit connections. Extracts and logs sub-reddit, page, and search if found.
# liburdi.joshua@gmail.com
# 2014

@load base/protocols/http

module Reddit;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ts:         time    &log;
    id:         conn_id &log;
    sub_reddit: string  &log    &optional;
    page:       string  &log    &optional;
    search:     string  &log    &optional;
  };

  global log_reddit: event(rec: Info);
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
# stop processing the event if an endpoint is not connecting to Reddit
if ( ! is_orig || ! c$http?$host || ! c$http?$uri ) return;
if ( c$http$host != "www.reddit.com" ) return;

local rec: Reddit::Info = [$ts=network_time(), $id=c$id];

if ( "/r/" in c$http$uri )
  {
  local clean_sub_reddit = find_last(c$http$uri,/\/r\/.*/);
  local sub_reddit_parts = split_all(clean_sub_reddit,/\//);
  if ( |sub_reddit_parts| >= 5 )
    rec$sub_reddit = sub_reddit_parts[5];
  }

if ( "/comments/" in c$http$uri )
  {
  local clean_comments = find_last(c$http$uri,/\/comments\/.*/);
  local comments_parts = split_all(clean_comments,/\//);
  local comments_size = |comments_parts|;
  rec$page = comments_parts[comments_size-2];
  }

if ( "?q=" in c$http$uri )
  {
  local clean_reddit_uri = find_last(c$http$uri,/\?q\=.*/);
  local uri_parts = split_all(clean_reddit_uri,/&/);
  local extract_reddit_search = split1(uri_parts[1],/\?q\=/);
  if ( |extract_reddit_search| >= 2 )
    rec$search = extract_reddit_search[2];
  }

Log::write(Reddit::LOG, rec);
}

event bro_init()
{
Log::create_stream(Reddit::LOG, [$columns=Info]);
}
