global count_404 : table[addr] of count;
global count_all_response : table[addr] of count;
global set_uri : table[addr] of set[string];

global begin_time:time; 
global end_time:time;
event zeek_init()
	{
	begin_time = current_time();
	end_time=begin_time + 10mins;
	count_404=table();
	count_all_response=table();
	set_uri=table();
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
		if(c$http$ts <= end_time)
		{
			if(c$id$orig_h in count_all_response)
				{
					count_all_response[c$id$orig_h]+=1;
				}
				else
				{
					count_all_response[c$id$orig_h]=1;
				}
		
			if(code==404)
			{
				if(c$id$orig_h in count_404)
				{
					count_404[c$id$orig_h]+=1;
				}
				else
				{
					count_404[c$id$orig_h]=1;
				}
				
				if(!(c$http$uri in set_uri[c$id$orig_h]))
				{
					add set_uri[c$id$orig_h][c$http$uri];
				}
			}
			
		}
		else
		{
			for(orig_h in count_404)
			{
				if(count_404[orig_h]>2)
				{
					if((count_404[orig_h]/count_all_response[orig_h])>0.2)
					{
						if(|set_uri[orig_h]|/count_404[orig_h]>0.5)
						{
							print fmt("%s is a scanner with %s scan attemps on %s urls", orig_h,count_404[orig_h],|set_uri[orig_h]|);
						}
					}
				}
			}
			
			begin_time = c$http$ts;
			end_time=begin_time + 10mins;
			count_404=table();
			count_all_response=table();
			set_uri=table();
			
			if(c$id$orig_h in count_all_response)
				{
					count_all_response[c$id$orig_h]+=1;
				}
				else
				{
					count_all_response[c$id$orig_h]=1;
				}
		
			if(code==404)
			{
				if(c$id$orig_h in count_404)
				{
					count_404[c$id$orig_h]+=1;
				}
				else
				{
					count_404[c$id$orig_h]=1;
				}
				
				if(!(c$http$uri in set_uri[c$id$orig_h]))
				{
					add set_uri[c$id$orig_h][c$http$uri];
				}
			}
			
		}
		
	}
	

event zeek_done()
	{
	print "finished";
	}
