<?php
namespace IPQualityScore\DB;

use Exception;

class DBReader
{
    /**
     * Usage: new DBReader("IPQualityScore-Reputation-IPV4-Database.ipqs");
     *
     * @param string $filename
     * @throws \IPQualityScore\DB\FileReaderException, \IPQualityScore\DB\IPNotFoundException
     * @return void
     */
    public function __construct($filename)
    {
        if (!file_exists($filename)) {
            throw new FileReaderException(
                "Invalid or non existant file name specified. Please check the file and try again.",
            );
        }

        $this->handler = fopen($filename, "rb");
        if ($this->handler === false) {
            throw new FileReaderException(
                "Invalid or non existant file name specified. Please check the file and try again.",
            );
        }

        $this->SetupHeaders();
        $this->SetupColumns();
        $this->SetupTreeHeaders();
    }

    /**
     * Usage: $record = $reader->Fetch("8.8.8.8");
     *
     * @param string $ip
     * @return \IPQualityScore\DB\IPQSRecord
     */
    public function Fetch($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new FileReaderException(
                "Attemtped to look up invalid IP address. Aborting.",
            );
        }

        if (
            $this->ipv6 === true &&
            !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
        ) {
            throw new FileReaderException(
                "Attemtped to look up IPv4 using IPv6 database file. Aborting.",
            );
        }

        if (
            $this->ipv6 === false &&
            !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
        ) {
            throw new FileReaderException(
                "Attemtped to look up IPv6 using IPv4 database file. Aborting.",
            );
        }

        if ($this->ipv6 === false) {
            //NOTE: this "magic number" is ip2long(0.255.255.255)
            if (ip2long($ip) <= 16777215) {
                throw new Exception(
                    "Attempted to look up ip in 0.0.0.0/8 range. Aborting.",
                );
            }
        }

        list(, $subnet, ) = explode('/', "0.0.0.0/8");
        $incomingIP = ip2long($ip);
        if (ip2long($subnet) <= $incomingIP && $incomingIP <= ip2long('255.255.255.255')) {
            // ip is in acceptable range
        } else {
            throw new Exception("Attempted to look up ip in 0.0.0.0/8 range. Aborting.");
        }

        $position = 0;
        $previous = [];
        $literal = $this->IP2Literal($ip);
        $file_position =
            $this->tree_start +
            DBReader::SUPPORTED_READER_VERSIONS[$this->READER_VERSION][
                "BASE_TREE_BYTES"
            ];

        for ($l = 0; $l < 257; $l++) {
            $previous[$position] = $file_position;

            if (strlen($literal) <= $position) {
                throw new IPNotFoundException(
                    "Invalid or nonexistant IP address specified for lookup. (EID: 8)",
                );
            }

            if ($literal[$position] === "0") {
                $file_position = unpack(
                    "Vread",
                    $this->ReadAt(
                        $file_position,
                        DBReader::SUPPORTED_READER_VERSIONS[
                            $this->READER_VERSION
                        ]["TREE_BYTE_WIDTH"],
                    ),
                )["read"];
            } else {
                $file_position = unpack(
                    "Vread",
                    $this->ReadAt(
                        $file_position +
                            DBReader::SUPPORTED_READER_VERSIONS[
                                $this->READER_VERSION
                            ]["TREE_BYTE_WIDTH"],
                        DBReader::SUPPORTED_READER_VERSIONS[
                            $this->READER_VERSION
                        ]["TREE_BYTE_WIDTH"],
                    ),
                )["read"];
            }

            if ($this->blacklistfile !== true) {
                if ($file_position === 0) {
                    for ($i = 0; $i <= $position; $i++) {
                        if ($literal[$position - $i] === "1") {
                            $literal[$position - $i] = "0";

                            for (
                                $n = $position - $i + 1;
                                $n < strlen($literal);
                                $n++
                            ) {
                                $literal[$n] = "1";
                            }

                            $position = $position - $i;
                            $file_position = $previous[$position];
                            break;
                        }
                    }

                    continue;
                }
            }

            if ($file_position < $this->tree_end) {
                if ($file_position === 0) {
                    break;
                }

                $position++;
                continue;
            }

            // In theory we're at a record.
            try {
                $raw = $this->ReadAt($file_position, $this->record_bytes);
            } catch (Exception $e) {
                throw new IPNotFoundException(
                    "Invalid or nonexistant IP address specified for lookup. (EID: 11)",
                );
            }

            try {
                return $this->CreateRecord($raw);
            } catch (Exception $e) {
                throw new IPNotFoundException(
                    "Invalid or nonexistant IP address specified for lookup. (EID: 12)",
                );
            }
        }

        throw new IPNotFoundException(
            "Invalid or nonexistant IP address specified for lookup. (EID: 13)",
        );
    }

    /**
     * Retrieve a list of the columns this file contains.
     * NOTE: Will not contain values for the previously fetched record.
     * Call (\IPQualityScore\DB\IPQSRecord) $record->Columns() for that data.
     *
     * @return array of \IPQualityScore\DB\Column
     */
    public function GetColumns()
    {
        return $this->columns;
    }

    // Allow support for specific legacy versions
    protected $READER_VERSION;
    const SUPPORTED_READER_VERSIONS = [
        1 => [
            "BASE_TREE_BYTES" => 5,
            "TREE_BYTE_WIDTH" => 4,
            "HEADER_SIZE" => 11,
        ],
        2 => [
            "BASE_TREE_BYTES" => 9,
            "TREE_BYTE_WIDTH" => 8,
            "HEADER_SIZE" => 16,
        ],
    ];

    protected $ipv6;
    protected $handler;
    protected $tree_start;
    protected $tree_end;
    protected $binary_data;
    protected $record_bytes;
    protected $valid = false;
    protected $blacklistfile;
    protected $columns = [];

    const HEADERS = "Cfile_type/Cversion/C3header_bytes/vrecord_bytes/Vfile_bytes";

    protected function SetupHeaders()
    {
        // Dogwater, meet hotdogs. if you do not like this, commit me a solution you do like.
        // Pull the bytes for the version, without reading the whole header.                                                                                                                                                          |version|length|payload
        $currentPosition = ftell($this->handler); // save current position
        fseek($this->handler, 1, SEEK_SET);
        $version = unpack("C", $this->Read(1))[1];
        fseek($this->handler, $currentPosition, SEEK_SET); // revert to old position, so we can continue to read the file as normal.

        // Exit if not current version or specifically allowed legacy version
        if (
            key_exists((int) $version, DBReader::SUPPORTED_READER_VERSIONS) !==
            true
        ) {
            throw new FileReaderException("Invalid file version, EID 2.1");
        }

        // Save our file version for quick-use
        $this->READER_VERSION = (int) $version;

        try {
            $headers = unpack(
                static::HEADERS,
                $this->Read(
                    DBReader::SUPPORTED_READER_VERSIONS[$this->READER_VERSION][
                        "HEADER_SIZE"
                    ],
                ),
            );
        } catch (\Exception $e) {
            throw new FileReaderException(
                "Invalid file format, unable to read first " .
                    DBReader::SUPPORTED_READER_VERSIONS[$this->READER_VERSION][
                        "HEADER_SIZE"
                    ] .
                    " bytes. EID 1",
            );
        }

        if (!isset($headers["file_type"])) {
            throw new FileReaderException(
                "Invalid file format, invalid first byte. EID 1.",
            );
        }

        $file_type = BinaryOption::Create($headers["file_type"]);
        if ($file_type->Has(BinaryOption::IPv4Map)) {
            $this->valid = true;
            $this->ipv6 = false;
        }

        if ($file_type->Has(BinaryOption::IPv6Map)) {
            $this->valid = true;
            $this->ipv6 = true;
        }

        if ($file_type->Has(BinaryOption::BinaryData)) {
            $this->binary_data = true;
        }

        if ($file_type->Has(BinaryOption::BlacklistFile)) {
            $this->blacklistfile = true;
        }

        if ($this->valid === false) {
            throw new FileReaderException(
                "Invalid file format, invalid first byte. EID 1.",
            );
        }

        // redundant, but kept anyways. with love, socks.
        if (!isset($headers["version"])) {
            throw new FileReaderException(
                "Invalid file format, no version number found. EID 2.",
            );
        }

        if (
            !isset(
                $headers["header_bytes1"],
                $headers["header_bytes2"],
                $headers["header_bytes3"],
            )
        ) {
            throw new FileReaderException(
                "Invalid file format, invalid header bytes, EID 2.",
            );
        }

        $this->tree_start = $this->uVarInt([
            $headers["header_bytes1"],
            $headers["header_bytes2"],
            $headers["header_bytes3"],
        ]);
        if ($this->tree_start === 0) {
            throw new FileReaderException(
                "Invalid file format, invalid header bytes. EID 2",
            );
        }

        if (
            !isset($headers["record_bytes"]) ||
            $headers["record_bytes"] === 0
        ) {
            throw new FileReaderException(
                "Invalid file format, invalid record size. EID 3",
            );
        }

        $this->record_bytes = $headers["record_bytes"];

        if (!isset($headers["file_bytes"]) || $headers["file_bytes"] === 0) {
            throw new FileReaderException(
                "Invalid file format, invalid file size. EID 3",
            );
        }

    }

    const COLUNN_HEADER = "x%s/a23name/Cvalue";
    protected function SetupColumns()
    {
        $length =
            $this->tree_start -
            DBReader::SUPPORTED_READER_VERSIONS[$this->READER_VERSION][
                "HEADER_SIZE"
            ];
        $column_data = $this->Read($length);

        for ($i = 0; $i < $length / 24; $i++) {
            $values = unpack(
                sprintf(static::COLUNN_HEADER, $i * 24),
                $column_data,
            );
            $this->columns[] = Column::Create(
                $values["name"],
                BinaryOption::Create($values["value"]),
            );
        }

        if (count($this->columns) === 0) {
            throw new FileReaderException(
                "File does not appear to be valid, no column data found. EID: 5",
            );
        }
    }

    protected function SetupTreeHeaders()
    {
        $tree = unpack(
            "Cheader/Vtree_bytes",
            $this->Read(
                DBReader::SUPPORTED_READER_VERSIONS[$this->READER_VERSION][
                    "BASE_TREE_BYTES"
                ],
            ),
        );
        if (
            !isset($tree["header"], $tree["tree_bytes"]) ||
            $tree["tree_bytes"] === 0 ||
            BinaryOption::Create($tree["header"])->Has(
                BinaryOption::TreeData,
            ) === false
        ) {
            throw new FileReaderException(
                "File does not appear to be valid, bad binary tree. EID: 6",
            );
        }

        $this->tree_end = $tree["tree_bytes"] + $this->tree_start;
    }

    protected function IP2Literal($ip)
    {
        $result = "";
        if ($this->ipv6) {
            foreach (explode(":", static::expand($ip)) as $block) {
                $result .= str_pad(
                    base_convert($block, 16, 2),
                    16,
                    "0",
                    STR_PAD_LEFT,
                );
            }
        } else {
            foreach (explode(".", $ip) as $block) {
                $result .= sprintf("%08d", decbin($block));
            }
        }

        return $result;
    }

    const BINARY_DATA_HEADER = "Cone/Ctwo/Cthree";
    const NONBINARY_DATA_HEADER = "Cone";
    protected function CreateRecord($raw)
    {
        $record = new IPQSRecord();

        $current_byte = 0;
        if ($this->binary_data) {
            $bytes = unpack(static::BINARY_DATA_HEADER, $raw);
            $record->ParseFirstByte(BinaryOption::Create($bytes["one"]));
            $record->ParseSecondByte(BinaryOption::Create($bytes["two"]));

            $third = BinaryOption::Create($bytes["three"]);
            $record->ConnectionTypeRaw($third);
            $record->AbuseVelocityRaw($third);
            $current_byte = 3;
        } else {
            $bytes = unpack(static::BINARY_DATA_HEADER, $raw);

            $first = BinaryOption::Create($bytes["one"]);
            $record->ConnectionTypeRaw($first);
            $record->AbuseVelocityRaw($first);
            $current_byte = 1;
        }

        foreach ($this->columns as $column) {
            $value = "";
            switch ($column->Name()) {
                case "ASN":
                    $value = unpack("x{$current_byte}/Vvalue", $raw)["value"];
                    $record->ASN((int) $value);
                    $current_byte += 4;
                    break;
                case "Latitude":
                    $value = unpack("x{$current_byte}/gvalue", $raw)["value"];
                    $record->Latitude((float) $value);
                    $current_byte += 4;
                    break;
                case "Longitude":
                    $value = unpack("x{$current_byte}/gvalue", $raw)["value"];
                    $record->Longitude((float) $value);
                    $current_byte += 4;
                    break;
                case "ZeroFraudScore":
                    $value = unpack("Cbyte", $raw[$current_byte])["byte"];
                    $record->SetFraudScore(0, (int) $value);
                    $current_byte++;
                    break;
                case "OneFraudScore":
                    $value = unpack("Cbyte", $raw[$current_byte])["byte"];
                    $record->SetFraudScore(0, (int) $value);
                    $current_byte++;
                    break;
                default:
                    if ($column->Type()->Has(BinaryOption::StringData)) {
                        $value = $this->GetRangedStringValue(
                            unpack("x{$current_byte}/Vvalue", $raw)["value"],
                        );
                        $current_byte +=
                            DBReader::SUPPORTED_READER_VERSIONS[
                                $this->READER_VERSION
                            ]["TREE_BYTE_WIDTH"];

                        if (method_exists($record, $column->Name())) {
                            $record->{$column->Name()}($value);
                        }
                    }
            }

            $record->AddColumn(
                Column::Create($column->Name(), $column->Type(), $value),
            );
        }

        return $record;
    }

    protected function GetRangedStringValue($position)
    {
        $bytes = unpack("Cbyte", $this->ReadAt($position, 1))["byte"];
        return unpack(
            "a{$bytes}value",
            $this->ReadRangedStringValue($bytes),
        )["value"]; // Read N bytes from position.
    }

    protected function ReadRangedStringValue($bytes)
    {
        $data = "";

        if ($bytes > 0) {
            $raw = fread($this->handler, $bytes);
            if ($raw !== false) {
                $data = $raw;
            }
        }

        return $data;
    }

    /*
     * Thanks to https://stackoverflow.com/questions/12095835/quick-way-of-expanding-ipv6-addresses-with-php
     */
    protected static function expand($ip)
    {
        $hex = unpack("H*hex", inet_pton($ip));
        return substr(
            preg_replace("/([A-f0-9]{4})/", "$1:", $hex["hex"]),
            0,
            -1,
        );
    }

    protected function Read($bytes)
    {
        $data = fread($this->handler, $bytes);
        if ($data === false) {
            throw new IPNotFoundException(
                "Unknown file format. Please check the file's integrity. EID 13",
            );
        }

        return $data;
    }

    protected function ReadAt($position, $bytes)
    {
        fseek($this->handler, $position);
        $data = fread($this->handler, $bytes);
        if ($data === false) {
            throw new IPNotFoundException(
                "Unknown file format. Please check the file's integrity. EID 14",
            );
        }

        return $data;
    }

    protected function uVarInt($bytes)
    {
        $x = 0;
        $s = 0;
        for ($i = 0; $i < count($bytes); $i++) {
            $b = $bytes[$i];
            if ($b < 0x80) {
                return $x | ($b << $s);
            }

            $x |= $b & (0x7f << $s);
            $s += 7;
        }

        return 0;
    }
}
