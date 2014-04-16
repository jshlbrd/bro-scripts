# Detects multiple instances of a single indicator in a connection or multiple indicators in a connection
# Josh Liburdi 2014-04-16

@load base/frameworks/notice
@load base/frameworks/intel

module Intel;

export {

    redef enum Notice::Type += {
        Unique_Indicators,
        Multiple_Indicators
    };

    # Threshold for processing unique indicators
    const intel_uniq_threshold: double = 1 &redef;
    # Threshold to meet before sending notice for multiple indicators
    const intel_mult_threshold: double = 5 &redef;
    # The amount of time to watch a connection for indicators
    # TODO verify at what time in connection indicators may be seen as this could impact how long to watch for indicators
    const intel_interval = 10 mins &redef;
}

event log_intel(rec: Info)
{
SumStats::observe("intel.stats", [$str=cat(rec$uid,"`",rec$id$orig_h,"`",rec$id$resp_h)], [$str=rec$seen$indicator]);
}

event bro_init()
  {
  local r1: SumStats::Reducer = [$stream="intel.stats", $apply=set(SumStats::UNIQUE)];
  SumStats::create([$name="correlate-intel",
                    $epoch=intel_interval,
                    $reducers=set(r1),
                    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                      local r = result["intel.stats"];
                      local parts = split_all(key$str,/`/);
                      local sub_msg = fmt("Indicators:");
                      local vals = r$unique_vals;
                      if ( r$unique > intel_uniq_threshold )
                        {
                        for ( i in vals  )
                          sub_msg = fmt("%s%s", sub_msg, " " + i$str);
                        local uniq_message = fmt("Seen %d uniq indicators in connection %s", r$unique, parts[1]);
                        NOTICE([$note=Multiple_Indicators,
                                $src=to_addr(parts[3]),
                                $dst=to_addr(parts[5]),
                                $msg=uniq_message,
                                $sub=sub_msg,
                                $identifier=key$str]);
                          }
                      if ( r$unique == intel_uniq_threshold && r$num >= intel_mult_threshold )
                        {
                        local mult_message = fmt("Seen indicator %s %d times in connection %s", i$str, r$num, parts[1]);
                        NOTICE([$note=Unique_Indicators,
                                $src=to_addr(parts[3]),
                                $dst=to_addr(parts[5]),
                                $msg=mult_message,
                                $sub=sub_msg,
                                $identifier=key$str]);
                        }
                        }]);
  }
