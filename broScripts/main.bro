@load base/frameworks/notice
@load base/utils/addrs
@load base/utils/directions-and-hosts

module SMTP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time when the message was first seen.
		ts:                time            ;
		## Unique ID for the connection.
		uid:               string          ;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                conn_id         ;
		## A count to represent the depth of this message transaction in
		## a single connection where multiple messages were transferred.
		trans_depth:       count           ;
		## Contents of the Helo header.
		helo:              string          &optional;
		## Contents of the From header.
		mailfrom:          string          &optional;
		## Contents of the Rcpt header.
		rcptto:            set[string]     &optional;
		## Contents of the Date header.
		date:              string          &optional;
		## Contents of the From header.
		from:              string          &optional;
		## Contents of the To header.
		to:                set[string]     &optional;
		## Contents of the CC header.
		cc:                set[string]     &optional;
		## Contents of the ReplyTo header.
		reply_to:          string          &optional;
		## Contents of the MsgID header.
		msg_id:            string          &optional;
		## Contents of the In-Reply-To header.
		in_reply_to:       string          &optional;
		## Contents of the Subject header.
		subject:           string          &optional;
		## Contents of the X-Originating-IP header.
		x_originating_ip:  addr            &optional;
		## Contents of the first Received header.
		first_received:    string          &optional;
		## Contents of the second Received header.
		second_received:   string          &optional;
		## Contents of the third Received header.
		third_received:   string           &optional;
		## Contents of the four Received header.
		fourth_received:   string          &optional;
		## Contents of the five Received header.
		five_received:   string          &optional;
		## The last message that the server sent to the client.
		last_reply:        string          &optional;
		## The message transmission path, as extracted from the headers.
		path:              vector of addr  &optional;
		## Value of the User-Agent header from the client.
		user_agent:        string          &optional;

		## Indicates that the connection has switched to using TLS.
		tls:               bool            &default=F;
		## Indicates if the "Received: from" headers should still be
		## processed.
		process_received_from: bool        &default=T;
		## Indicates if client activity has been seen, but not yet logged.
		has_client_activity:  bool            &default=F;

		## Keeps track of the order that the headers came in
		headerKV:      string          &log; 
	};

	type State: record {
		helo:                     string    &optional;
		## Count the number of individual messages transmitted during
		## this SMTP session.  Note, this is not the number of
		## recipients, but the number of message bodies transferred.
		messages_transferred:     count     &default=0;

		pending_messages:         set[Info] &optional;
	};

	## Direction to capture the full "Received from" path.
	##    REMOTE_HOSTS - only capture the path until an internal host is found.
	##    LOCAL_HOSTS - only capture the path until the external host is discovered.
	##    ALL_HOSTS - always capture the entire path.
	##    NO_HOSTS - never capture the path.
	const mail_path_capture = ALL_HOSTS &redef;

	## Create an extremely shortened representation of a log line.
	global describe: function(rec: Info): string;

	global log_smtp: event(rec: Info);
}

redef record connection += {
	smtp:       Info  &optional;
	smtp_state: State &optional;
};

const ports = { 25/tcp, 587/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(SMTP::LOG, [$columns=SMTP::Info, $ev=log_smtp, $path="smtp"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, ports);
	}

function find_address_in_smtp_header(header: string): string
{
	local ips = extract_ip_addresses(header);
	# If there are more than one IP address found, return the second.
	if ( |ips| > 1 )
		return ips[1];
	# Otherwise, return the first.
	else if ( |ips| > 0 )
		return ips[0];
	# Otherwise, there wasn't an IP address found.
	else
		return "";
}

function new_smtp_log(c: connection): Info
	{
	local l: Info;
	l$ts=network_time();
	l$uid=c$uid;
	l$id=c$id;
	# The messages_transferred count isn't incremented until the message is
	# finished so we need to increment the count by 1 here.
	l$trans_depth = c$smtp_state$messages_transferred+1;

	if ( c$smtp_state?$helo )
		l$helo = c$smtp_state$helo;

	# The path will always end with the hosts involved in this connection.
	# The lower values in the vector are the end of the path.
	l$path = vector(c$id$resp_h, c$id$orig_h);

	return l;
	}

function set_smtp_session(c: connection)
	{
	if ( ! c?$smtp_state )
		c$smtp_state = [];

	if ( ! c?$smtp )
		c$smtp = new_smtp_log(c);
	}

function smtp_message(c: connection)
	{
	if ( c$smtp$has_client_activity )
		{
		Log::write(SMTP::LOG, c$smtp);
		c$smtp = new_smtp_log(c);
		}
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	set_smtp_session(c);
	local upper_command = to_upper(command);

	if ( upper_command == "HELO" || upper_command == "EHLO" )
		{
		c$smtp_state$helo = arg;
		c$smtp$helo = arg;
		}

	else if ( upper_command == "RCPT" && /^[tT][oO]:/ in arg )
		{
		if ( ! c$smtp?$rcptto )
			c$smtp$rcptto = set();
		add c$smtp$rcptto[split_string1(arg, /:[[:blank:]]*/)[1]];
		c$smtp$has_client_activity = T;
		}

	else if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg )
		{
		# Flush last message in case we didn't see the server's acknowledgement.
		smtp_message(c);

		local partially_done = split_string1(arg, /:[[:blank:]]*/)[1];
		c$smtp$mailfrom = split_string1(partially_done, /[[:blank:]]?/)[0];
		c$smtp$has_client_activity = T;
		}
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=5
	{
	set_smtp_session(c);

	# This continually overwrites, but we want the last reply,
	# so this actually works fine.
	c$smtp$last_reply = fmt("%d %s", code, msg);
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=-5
	{
	if ( cmd == "." )
		{
		# Track the number of messages seen in this session.
		++c$smtp_state$messages_transferred;
		smtp_message(c);
		c$smtp = new_smtp_log(c);
		}
	}


event mime_one_header(c: connection, h: mime_header_rec) &priority=5
	{
	if ( ! c?$smtp ) return;
		local name = h$name;
		local value = h$value;

		name = gsub(name, /'/, "\'");
		name = gsub(name, /\"/, "\"");
		name = gsub(name, /\\/, "\\");
		name = escape_string(name);

		value = gsub(value, /'/, "\'");
		value = gsub(value, /\"/, "\"");
		value = gsub(value, /\\/, "\\");
		value = escape_string(value);

		# record order
		if ( c$smtp?$headerKV ){
			c$smtp$headerKV = c$smtp$headerKV[:-1];
			c$smtp$headerKV = string_cat(c$smtp$headerKV, ", ('", name, "','", value, "')]");
		}else{
			c$smtp$headerKV = "[";
			c$smtp$headerKV = string_cat(c$smtp$headerKV, "('", name, "','", value, "')]");
		}
	}

# This event handler builds the "Received From" path by reading the
# headers in the mail
event mime_one_header(c: connection, h: mime_header_rec) &priority=3
	{
	# If we've decided that we're done watching the received headers for
	# whatever reason, we're done.  Could be due to only watching until
	# local addresses are seen in the received from headers.
	if ( ! c?$smtp || h$name != "RECEIVED" || ! c$smtp$process_received_from )
		return;

	local text_ip = find_address_in_smtp_header(h$value);
	if ( text_ip == "" )
		return;
	local ip = to_addr(text_ip);

	if ( ! addr_matches_host(ip, mail_path_capture) &&
	     ! Site::is_private_addr(ip) )
		{
		c$smtp$process_received_from = F;
		}
	if ( c$smtp$path[|c$smtp$path|-1] != ip )
		c$smtp$path[|c$smtp$path|] = ip;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$smtp )
		smtp_message(c);
	}

event smtp_starttls(c: connection) &priority=5
	{
	if ( c?$smtp )
		{
		c$smtp$tls = T;
		c$smtp$has_client_activity = T;
		}
	}

function describe(rec: Info): string
	{
	if ( rec?$mailfrom && rec?$rcptto )
		{
		local one_to = "";
		for ( to in rec$rcptto )
			{
			one_to = to;
			break;
			}
		local abbrev_subject = "";
		if ( rec?$subject )
			{
			if ( |rec$subject| > 20 )
				{
				abbrev_subject = rec$subject[0:21] + "...";
				}
			}

		return fmt("%s -> %s%s%s", rec$mailfrom, one_to,
			(|rec$rcptto|>1 ? fmt(" (plus %d others)", |rec$rcptto|-1) : ""),
			(abbrev_subject != "" ? fmt(": %s", abbrev_subject) : ""));
		}
		return "";
	}
