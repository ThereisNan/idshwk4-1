@load base/frameworks/sumstats
global tURL: string;

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="404.response", $apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="unique.url", $apply=set(SumStats::UNIQUE));
	SumStats::create([$name="scanner.detect",
					  $epoch=10mins,
					  $reducers=set(r1, r2, r3),
					  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
					  {
						  local s1 = result["404.response"];
						  local s2 = result["response"];
						  local s3 = result["unique.url"];
						  if(s1$sum > 2)
						  {
							  if(s1$sum / s2$sum > 0.2)
							  {
								  if((s3$unique as double) / s1$sum > 0.5)
								  {
									  print fmt("%s is a scanner with %d scan attempts on %d urls.", key$host, s1$num, s3$unique);
								  }
							  }
						  }
					  };
	]);
}

event http_request(c: connection, method: string, original_URL: string, unescaped_URL: string, version: string)
{
	tURL = unescaped_URL;
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	if(code == 404)
	{
		SumStats::observe("404_response", [$host=c$id$orig_h], [$num=1]);
		SumStats::observe("unique.url", [$host=c$id$orig_h], [$str=tURL]);
	}
	SumStats::observe("response", [$host=c$id$orig_h], [$num=1]);
}
