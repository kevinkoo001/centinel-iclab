<?php
header("Content-Type: text/plain");
function receivePOST($variableName)
{
	return htmlspecialchars($_POST[$variableName]);
}

$storage = receivePOST("url_storage");

$urls = explode("!@:,,[],|||", $storage);

echo "[URLS]\n";
echo "url_list = " . $urls[0] . "\n";
for ($key = 1, $size = count($urls); $key < $size; $key++) 
{
	echo "     " . $urls[$key] . "\n";
}

$ping_check = receivePOST("Ping");
$dns_check = receivePOST("Dns");
$http_check = receivePOST("HTTP");
$traceroute_check = receivePOST("Traceroute");
$tcp_check = receivePOST("TCP");

if ($ping_check)
{
	echo "\n[Ping]\n";
	echo "packets=" . receivePOST("ping_packets") . "\n";
	echo "timeout=" . receivePOST("ping_timeout") . "\n";
}
if ($dns_check)
{
	echo "\n[DNS]\n";
	echo "timeout=" . receivePOST("dns_timeout") . "\n";
	echo "record_types=" . receivePOST("dns_record_type") . "\n";
	echo "resolver=" . receivePOST("dns_resolver") . "\n";
}
if ($http_check)
{
	echo "\n[HTTP]\n";
	$header_storage = receivePOST("header_storage");
	$headers = explode("!@:,,[],|||", $header_storage);
	foreach ($headers as $header)
	{
		if ($header != "")
		{
			$data = explode(": ", $header);
			$value = "";
			for ($key = 1, $size = count($data); $key < $size; $key++) 
			{		
				$next_value = $data[$key];
				if ($key != $size - 1)
				{
					$next_value .= ": ";
				}
				$value .= $next_value;
			}
			
			echo "header_" . $data[0] . "=" . $value . "\n";
		}
	}
}
if ($traceroute_check)
{
	echo "\n[Traceroute]\n";
	echo "timeout=" . receivePOST("traceroute_timeout") . "\n";
	echo "start_hop=" . receivePOST("traceroute_start_hop") . "\n";
	echo "max_hops=" . receivePOST("traceroute_max_hops") . "\n";
}
if ($tcp_check)
{
	echo "\n[TCP]\n";
	echo "port=" . receivePOST("tcp_port") . "\n";
}
?>