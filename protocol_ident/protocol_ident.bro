# This script and any accompanying signature files provide a method of identifying 
# protocols without requiring protocol analyzers 
# Josh Liburdi 2015

redef record Conn::Info += {
	protocol_ident:	set[string] &log &optional;
};

# A table that stores uid and protocol mappings. Each uid can have multiple
# protocols associated with it.
global uid_protocol_map: table[string] of set[string];

# Stores any identified protocols in connection records
function store_protocol_ident(mapping: table[string] of set[string], uid: string, protocol: string)
	{
	if ( uid !in uid_protocol_map )
		uid_protocol_map[uid] = set();
	add uid_protocol_map[uid][protocol];
	}

# Sets any identified protocols in connection records
function set_protocol_ident(c: connection)
	{
	if ( c$uid in uid_protocol_map )
		{
		if ( ! c$conn?$protocol_ident )
			c$conn$protocol_ident = set();
		c$conn$protocol_ident = uid_protocol_map[c$uid];
		delete uid_protocol_map[c$uid]; 
		}
	}

function protocol_ident::found(state: signature_state, data: string): bool
	{
	# Each evaluated signature ID is parsed so that a string value, which 
	# should contain the protocol name, is extracted
	local protocol_ident = sub(state$sig_id,/^.*_/,"");
	# Each identified protocol is mapped with the uid it was seen in 
	# and stored in a table 
	store_protocol_ident(uid_protocol_map,state$conn$uid,protocol_ident);

	return F;
	}


event connection_state_remove(c: connection)
	{
	# If a protocol was attached to a connection and triggered by DPD, 
	# then we piggyback the c$service value(s) instead of re-performing 
	# signature matches
	if ( |c$service| > 0 )
		for ( protocol_ident in c$service )
			{
			if ( /^-/ in protocol_ident )
				next;
			protocol_ident = to_lower(protocol_ident);
			store_protocol_ident(uid_protocol_map,c$uid,protocol_ident);
			}

	set_protocol_ident(c);
	}
