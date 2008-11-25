-module (stitcho_lib).
-export ([signup/4, send/7]).
-define (HOSTNAME, "http://api.stitcho.com").

signup(PartnerID, SignKey, Email, Message) -> 
	UnsignedQuery = f("p=~p&e=~s&m=~s", [PartnerID, url_encode(clean_lower(Email)), url_encode(Message)]),
	Signature = sign(UnsignedQuery, SignKey),
	SignedRequest = f(?HOSTNAME ++ "/api/partner/signup?~s&s=~s", [UnsignedQuery, Signature]),
	
	% Do the request...
	{ok, {{_Version, StatusCode, _StatusMessage}, _Headers, _Response}} = http:request(SignedRequest),
	StatusCode.

send(PartnerID, SignKey, Email, IconID, Title, Message, Url) ->
	{ok, MD5} = hex_encode(erlang:md5(clean_lower(Email))),
	UnsignedQuery = f("p=~p&md5=~s&i=~p&t=~s&m=~s&u=~s", [PartnerID, MD5, IconID, url_encode(Title), url_encode(Message), url_encode(Url)]),
	Signature = sign(UnsignedQuery, SignKey),
	SignedRequest = f(?HOSTNAME ++ "/api/partner/send?~s&s=~s", [UnsignedQuery, Signature]),

	% Do the request...
	{ok, {{_Version, StatusCode, _StatusMessage}, _Headers, _Response}} = http:request(SignedRequest),
	StatusCode.
	
%%% PRIVATE FUNCTIONS %%%

clean_lower(L) -> string:strip(string:to_lower(L)).

url_encode(S) -> url_encode(list_to_binary(S), <<>>).
url_encode(<<H, Rest/binary>>, Acc) ->
	if
		H >= $a, $z >= H ->
			url_encode(Rest, <<Acc/binary, H>>);
		H >= $A, $Z >= H ->
			url_encode(Rest, <<Acc/binary, H>>);
		H >= $0, $9 >= H ->
			url_encode(Rest, <<Acc/binary, H>>);
		H == $_; H == $.; H == $-; H == $/; H == $: -> % FIXME: more..
			url_encode(Rest, <<Acc/binary, H>>);
		true ->
			case yaws:integer_to_hex(H) of
				[X, Y] ->
					url_encode(Rest, <<Acc/binary, $%, X, Y>>);
				[X] ->
					url_encode(Rest, <<Acc/binary, $%, $0, X>>)
			end
    end;
url_encode(<<>>, Acc) -> Acc.

hex_encode(Data) -> encode(Data, 16).
encode(Data, Base) when is_binary(Data) -> encode(binary_to_list(Data), Base);
encode(Data, Base) when is_list(Data) ->
	F = fun(C) when is_integer(C) ->
		case erlang:integer_to_list(C, Base) of
			[C1, C2] -> <<C1, C2>>;
			[C1]     -> <<$0, C1>>;
			_        -> throw("Could not hex_encode the string.")
		end
	end,
	{ok, list_to_binary([F(I) || I <- Data])}.

f(S, Args) -> lists:flatten(io_lib:format(S, Args)).
	
sign(Message, SignKey) ->
	Signature1 = erlang:md5(wf:f("~s~s", [Message, SignKey])),
	{ok, Signature2} = wf_utils:hex_encode(Signature1),
	Signature2.
	