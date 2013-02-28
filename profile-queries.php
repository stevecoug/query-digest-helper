#!/usr/bin/php
<?

$FILTER = "port 3306";
$RUNTIME = 10;
$TMPDIR = sys_get_temp_dir();

// Get our arguments
for ($i = 1; $i < $argc; $i++) {
	switch ($argv[$i]) {
		case "--filter":
		case "-f":
			$FILTER .= " and " . $argv[++$i];
		break;
		
		case "--run-time":
		case "-r":
			$RUNTIME = floatval($argv[++$i]);
		break;
		
		default:
			printf("Invalid argument: %s\n\n"; $argv[$i]);
			printf("Usage: %s [--filter <tcpdump filter>] [--run-time <seconds>]\n\n", $argv[0]);
			exit(1);
		break;
	}
}


// Run tcpdump and output to a temporary file
$descriptors = array(
	0 => array("pipe", "r"),
	1 => array("pipe", "w"),
	2 => array("pipe", "w"),
);


$pcap = tempnam($TMPDIR, "pcap");
$proc = proc_open("tcpdump -s 0 -x -n -q -tttt $FILTER > $pcap", $descriptors, $pipes);
fclose($pipes[0]);
sleep($RUNTIME);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($proc);


// Run pt-query-digest on the output of tcpdump
$output = tempnam($TMPDIR, "digest");
system("pt-query-digest --print --type tcpdump $pcap > $output");


// Parse the pt-query-digest output and group queries that are similar
$fp = fopen($output, 'r');

$CONSTANT = " *('[^']*'|NULL|[0-9.-]+|0x[0-9a-fA-F]+|[Nn][Oo][Ww]\(\)) *";
$mode = 0;
$comment = $sql = "";
while ($line = fgets($fp, 4096)) {
	$line = trim($line);
	if ($mode === 0 && substr($line, 0, 13) === "# Query_time:") {
		$comment = $line;
		$mode = 1;
	} else if ($mode === 1) {
		if (substr($line, 0, 7) !== "# Time:") {
			$sql .= "$line ";
		} else {
			$sql = trim($sql);
			$sql = str_replace("\\'", "", $sql);
			$sql = preg_replace("/ ?([=!<>]+) ?$CONSTANT/", "\\1'' ", $sql);
			$sql = preg_replace("/ ?BETWEEN $CONSTANT AND $CONSTANT ?/i", "BETWEEN '' AND '' ", $sql);
			$sql = preg_replace("/\(($CONSTANT,)*$CONSTANT\)/", "()", $sql);
			$sql = preg_replace('/^use [^;]+; /', '', $sql);
			echo "$sql\n";
			$mode = 0;
			$comment = $sql = "";
		}
	}
}
fclose($fp);


?>
