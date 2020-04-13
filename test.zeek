@load base/frameworks/sumstats
global tURL: string;

event zeek_init()
{
	local r1 = Sumstats::Reducer($stream="404.response", $apply=set(Sumstats::SUM));
	local r2 = Sumstats::Reducer($stream="response", $apply=set(Sumstats::SUM));
	local r3 = Sumstats::Reducer($stream="unique.url", $apply=set(Sumstats::UNIQUE));
	Sumstats::create([$name="scanner.detect",
					  $epoch=10mins,
					  $reducers=set(r1, r2, r3),
					  $epoch_result(ts: time, key: Sumstats::Key, result: Sumstats::Result) = 
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
		Sumstats::observe("404_response", [$host=c$id$orig_h], [$num=1]);
		Sumstats::observe("unique.url", [$host=c$id$orig_h], [$str=tURL]);
	}
	Sumstas::observe("response", [$host=c$id$orig_h], [$num=1]);
}
