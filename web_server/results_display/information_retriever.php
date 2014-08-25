<?php

function startsWith($haystack, $needle)
{
     $length = strlen($needle);
     return (substr($haystack, 0, $length) === $needle);
}

function endsWith($string, $test) {
    $strlen = strlen($string);
    $testlen = strlen($test);
    if ($testlen > $strlen) return false;
    return substr_compare($string, $test, $strlen - $testlen, $testlen) === 0;
}

function strcontains($haystack, $needle)
{
	if (strpos($haystack,$needle) !== false) {
		return true;
	}
	else
	{
		return false;
	}
}

function array_contains_array($array)
{
	foreach ($array as $item)
	{
		if (is_array($item))
		{
			return true;
		}
	}
	return false;
}

function recursive_parse($json, $root, $path, $showHtml, $decodeDns)
{	
	$arr = array_keys($json);
	$exploded = explode("/", $path);
	$depth = count($exploded);
	
	foreach ($arr as $key) 
	{
		if (is_array($json[$key]))
		{	
			
			if ($depth == 2)
			{
				$next = $json[$key];
				if (array_key_exists("url", $next))
				{
					echo $root . $next["url"] . ":\n"; 
				} 
				elseif (array_key_exists("host", $next)) # For backwards compatibility with older tests
				{
					echo $root . $next["host"] . ":\n"; 
				}
				else
				{
					echo $root . $key . ":\n";
				}
			} 
			else
			{
				echo $root . $key . ":\n";
			}
			
			recursive_parse($json[$key], $root . "----", $path . "/" . $key, $showHtml, $decodeDns);
		}
		else
		{
			if (strcontains($key, "body") && startsWith($path, "/std_http/"))
			{
				if ($showHtml == "true")
				{
					echo $root . $key . ": " . base64_decode($json[$key]) . "\n";
				}
				else
				{
					echo $root . $key . ": " . "[HTML Code Excluded]" . "\n";
				}
			}
			elseif (($key === "first_packet.b64" || $key === "second_packet.b64") && startsWith($path, "/std_dns/"))
			{
				if ($decodeDns == "true")
				{
					echo $root . $key . ": " . base64_decode($json[$key]) . "\n"; //This looks a bit ugly
				}
				else
				{
				echo $root . $key . ": " . $json[$key] . "\n";
				}
			}
			elseif (endsWith($key, ".b64"))
			{
				echo $root . $key . ": " . base64_decode($json[$key]) . "\n";
			}
			else
			{
			echo $root . $key . ": " . $json[$key] . "\n";
			}
		}
	}
	if ($depth == 2 || $depth == 3)
	{
		echo("\n");
	}
}

$RESULTS_DIR = "results_dir";
$type = $_POST["info"];

if ($type == "clienttags")
{
	$files = scandir($RESULTS_DIR);
	foreach ($files as $file)
	{
		if ($file != "." and $file != "..")
		{
			echo '<option value="' . $file . '">' . $file . '</option>';
		}
		
	}
	echo "<option selected disabled hidden value=\" \"></option>";

} 
elseif ($type == "experiments")
{
	$array = array();
	$dir = $RESULTS_DIR . '/' . $_POST["client_tag"];
	$files = scandir($dir);
	foreach ($files as $file)
	{
		if ($file != "." and $file != "..")
		{
			//$split_by_dash = explode("-",$file);
			//$name = $split_by_dash[0];
			$path = $dir . '/' . $file;
			$contents = file_get_contents($path, true);
			$json = json_decode($contents, true);
			$meta = $json["meta"];
			$exp = $meta["exp_name"];
			if (!in_array($exp, $array))
			{
				array_push($array, $exp);
			}
		}
		
	}
	
	foreach ($array as $test_name)
	{
		echo '<option value="' . $test_name . '">' . $test_name . '</option>';
	}
	echo "<option selected disabled hidden value=\" \"></option>";
}
elseif ($type == "ids")
{
	$dir = $RESULTS_DIR . '/' . $_POST["client_tag"];
	$files = scandir($dir);
	$experiment = $_POST["experiment"];
	$array = array();
	foreach ($files as $file)
	{
		if ($file == ".." || $file == ".")
		{
			continue;
		}
		$path = $dir . '/' . $file;
		$contents = file_get_contents($path, true);
		$json = json_decode($contents, true);
		$meta = $json["meta"];
		$id = $meta["run_id"];
		$exp = $meta["exp_name"];
		if ($exp == $experiment){
			echo '<option name=' . $path . ' value="' . $id . '">' . $id . '</option>';
		}
		/*if (startsWith($file, $experiment))
		{
			$exp = explode("-", $file);
			$id = $exp[1];
			$path = $dir . '/' . $file;
			echo '<option name=' . $path . ' value="' . $id . '">' . $id . '</option>';
		} */
	}
	echo "<option selected disabled hidden value=\" \"></option>";
} elseif ($type == "json")
{
	$path = $_POST["path"];
	$contents = file_get_contents($path, true);
	$json = json_decode($contents, true);
	$html = $_POST["html"];
	$dns = $_POST["dns"];
	recursive_parse($json, '', '', $html, $dns);

}
?>