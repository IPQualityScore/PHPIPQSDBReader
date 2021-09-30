<?php
namespace IPQualityScore\DB;

use Exception;

class DBReader {    
    /**
     * Usage: new DBReader("IPQualityScore-Reputation-IPV4-Database.ipqs");
     *
     * @param string $filename
     * @throws \IPQualityScore\DB\FileReaderException, \IPQualityScore\DB\IPNotFoundException
     * @return void
     */
    public function __construct($filename){
        if(!file_exists($filename)){
            throw new FileReaderException("Invalid or non existant file name specified. Please check the file and try again.");
        }

        $this->handler = fopen($filename, "rb");
        if($this->handler === false){
            throw new FileReaderException("Invalid or non existant file name specified. Please check the file and try again.");
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
    public function Fetch($ip){
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new FileReaderException("Attemtped to look up invalid IP address. Aborting.");
        }

        if($this->ipv6 === true && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
           throw new FileReaderException("Attemtped to look up IPv4 using IPv6 database file. Aborting.");
        }

        if($this->ipv6 === false && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){
            throw new FileReaderException("Attemtped to look up IPv6 using IPv4 database file. Aborting.");
        }

        $literal = $this->IP2Literal($ip);
        $position = 0;

        $file_position = $this->tree_start + static::BASE_TREE_BYTES;

        while(true){
            if(strlen($literal) <= $position){
                throw new IPNotFoundException("Invalid or nonexistant IP address specified for lookup. (EID: 8)");
            }

            $next = 0;
            try {
                if($literal[$position] === "0"){
                    $pos = $this->ReadAt($file_position, static::TREE_BYTE_WIDTH);
                    if(strlen($pos) === 4){
                        $next = unpack("Vread", $pos)['read'];
                    }
                } else {
                    $pos = $this->ReadAt($file_position + 4, static::TREE_BYTE_WIDTH);
                    if(strlen($pos) === 4){
                        $next = unpack("Vread", $pos)['read'];
                    }
                }
            } catch(Exception $e){
                throw new IPNotFoundException("Invalid or nonexistant IP address specified for lookup. (EID: 9)");
            }

            try {
                if($next === 0){
                    if($literal[$position] === "0"){
                        $pos = $this->ReadAt($file_position + 4, static::TREE_BYTE_WIDTH);
                        if(strlen($pos) === 4){
                            $next = unpack("Vread", $pos)['read'];
                        }

                        if($next === 0){
                            throw new IPNotFoundException();
                        }

                    } else {
                        $pos = $this->ReadAt($file_position, static::TREE_BYTE_WIDTH);
                        if(strlen($pos) === 4){
                            $next = unpack("Vread", $pos)['read'];
                        }

                        if($next === 0){
                            throw new IPNotFoundException();
                        }
                    }
                }
            } catch(Exception $e){
                throw new IPNotFoundException("Invalid or nonexistant IP address specified for lookup. (EID: 10)");
            }

            $file_position = $next;
            if($file_position < $this->tree_end){
                $position++;
                continue;
            }

            // In theory we're at a record.
            try {
                $raw = $this->ReadAt($file_position, $this->record_bytes);
            } catch(Exception $e){
                throw new IPNotFoundException("Invalid or nonexistant IP address specified for lookup. (EID: 11)");
            }

            try {
                return $this->CreateRecord($raw);
            } catch(Exception $e){
                throw new IPNotFoundException("Invalid or nonexistant IP address specified for lookup. (EID: 12)");
            }
        }
    }
    
    /**
     * Retrieve a list of the columns this file contains.
     * NOTE: Will not contain values for the previously fetched record.
     * Call (\IPQualityScore\DB\IPQSRecord) $record->Columns() for that data.
     * 
     * @return array of \IPQualityScore\DB\Column
     */
    public function GetColumns(){
        return $this->columns;
    }

    const READER_VERSION = 1;

    protected $ipv6;
    protected $handler;
    protected $tree_start;
    protected $tree_end;
    protected $binary_data;
    protected $record_bytes;
    protected $valid = false;
    protected $columns = array();

    const HEADERS = 'Cfile_type/Cversion/C3header_bytes/vrecord_bytes/Vfile_bytes';

    const BASE_TREE_BYTES = 5;
    const TREE_BYTE_WIDTH = 4;

    const BASE_HEADER_BYTES = 11;
    protected function SetupHeaders(){
        try {
            $headers = unpack(static::HEADERS, $this->Read(static::BASE_HEADER_BYTES));
        } catch(\Exception $e){
            throw new FileReaderException("Invalid file format, unable to read first 11 bytes. EID 1");
        }

        if(!isset($headers['file_type'])){
            throw new FileReaderException("Invalid file format, invalid first byte. EID 1.");
        }

        $file_type = BinaryOption::Create($headers['file_type']);
        if($file_type->Has(BinaryOption::IPv4Map)){
            $this->valid = true;
            $this->ipv6 = false;
        }

        if($file_type->Has(BinaryOption::IPv6Map)){
            $this->valid = true;
            $this->ipv6 = true;
        }

        if($file_type->Has(BinaryOption::BinaryData)){
            $this->binary_data = true;
        }

        if($this->valid === false){
            throw new FileReaderException("Invalid file format, invalid first byte. EID 1.");
        }

        if(!isset($headers['version'])){
            throw new FileReaderException("Invalid file format, no version number found. EID 2.");
        }

        if($headers['version'] !== DBReader::READER_VERSION){
            throw new FileReaderException("Invalid file version, EID 2.");
        }

        if(!isset($headers['header_bytes1'], $headers['header_bytes2'], $headers['header_bytes3'])){
            throw new FileReaderException("Invalid file format, invalid header bytes, EID 2.");
        }

        $this->tree_start = $this->uVarInt([$headers['header_bytes1'], $headers['header_bytes2'], $headers['header_bytes3']]);
        if($this->tree_start === 0){
            throw new FileReaderException("Invalid file format, invalid header bytes. EID 2");
        }

        if(!isset($headers['record_bytes']) || $headers['record_bytes'] === 0){
            throw new FileReaderException("Invalid file format, invalid record size. EID 3");
        }

        $this->record_bytes = $headers['record_bytes'];

        if(!isset($headers['file_bytes']) || $headers['file_bytes'] === 0){
            throw new FileReaderException("Invalid file format, invalid file size. EID 3");
        }
    }

    const COLUNN_HEADER = "x%s/a23name/Cvalue";
    protected function SetupColumns(){
        $length = $this->tree_start - static::BASE_HEADER_BYTES;
        $column_data = $this->Read($length);

        for($i=0;$i<$length/24;$i++){
            $values = unpack(sprintf(static::COLUNN_HEADER, $i * 24), $column_data);
            $this->columns[] = Column::Create($values['name'], BinaryOption::Create($values['value']));
        }

        if(count($this->columns) === 0){
            throw new FileReaderException("File does not appear to be valid, no column data found. EID: 5");
        }
    }

    protected function SetupTreeHeaders(){
        $tree = unpack("Cheader/Vtree_bytes", $this->Read(5));
        if(!isset($tree['header'], $tree['tree_bytes']) || $tree['tree_bytes'] === 0 || BinaryOption::Create($tree['header'])->Has(BinaryOption::TreeData) === false){
            throw new FileReaderException("File does not appear to be valid, bad binary tree. EID: 6");
        }

        $this->tree_end = $tree['tree_bytes'] + $this->tree_start;
    }

    protected function IP2Literal($ip){
        $result = "";
        if($this->ipv6){
            foreach(explode(':', static::expand($ip)) as $block){
                $result .= base_convert($block, 16, 2);
            }
        } else {
            foreach(explode('.', $ip) as $block){
                $result .= sprintf("%08d", decbin($block));
            }
        }

        return $result;
    }

    const BINARY_DATA_HEADER = "Cone/Ctwo/Cthree";
    const NONBINARY_DATA_HEADER = "Cone";
    protected function CreateRecord($raw){
        $record = new IPQSRecord();

        $current_byte = 0;
        if($this->binary_data){
            $bytes = unpack(static::BINARY_DATA_HEADER, $raw);
            $record->ParseFirstByte(BinaryOption::Create($bytes['one']));
            $record->ParseSecondByte(BinaryOption::Create($bytes['two']));

            $third = BinaryOption::Create($bytes['three']);
            $record->ConnectionTypeRaw($third);
            $record->AbuseVelocityRaw($third);
            $current_byte = 3;
        } else {
            $bytes = unpack(static::BINARY_DATA_HEADER, $raw);

            $first = BinaryOption::Create($bytes['one']);
            $record->ConnectionTypeRaw($first);
            $record->AbuseVelocityRaw($first);
            $current_byte = 1;
        }

        foreach($this->columns as $column){
            $value = "";
            switch($column->Name()){
                case "ASN":
                    $value = unpack("x{$current_byte}/Vvalue", $raw)['value'];
                    $record->ASN((int) $value);
                    $current_byte += 4;
                    break;
                case "Latitude":
                    $value = unpack("x{$current_byte}/gvalue", $raw)['value'];
                    $record->Latitude((float) $value);
                    $current_byte += 4;
                    break;
                case "Longitude":
                    $value = unpack("x{$current_byte}/gvalue", $raw)['value'];
                    $record->Longitude((float) $value);
                    $current_byte += 4;
                    break;
                case "ZeroFraudScore":
                    $value = unpack("Cbyte", $raw[$current_byte])['byte'];
                    $record->SetFraudScore(0, (int) $value);
                    $current_byte++;
                    break;
                case "OneFraudScore":
                    $value = unpack("Cbyte", $raw[$current_byte])['byte'];
                    $record->SetFraudScore(0, (int) $value);
                    $current_byte++;
                    break;
                default:
                    if($column->Type()->Has(BinaryOption::StringData)){
                        $value = $this->GetRangedStringValue(unpack("x{$current_byte}/Vvalue", $raw)['value']);
                        $current_byte += 4;

                        if(method_exists($record, $column->Name())){
                            $record->{$column->Name()}($value);
                        }
                    }

            }

            $record->AddColumn(Column::Create($column->Name(), $column->Type(), $value));
        }

        return $record;
    }

    protected function GetRangedStringValue($position){
        $bytes = unpack("Cbyte", $this->ReadAt($position, 1))['byte'];
        return unpack("a{$bytes}value", $this->Read($bytes))['value']; // Read N bytes from position.
    }

    /*
    * Thanks to https://stackoverflow.com/questions/12095835/quick-way-of-expanding-ipv6-addresses-with-php
    */
    protected static function expand($ip){
        $hex = unpack("H*hex", inet_pton($ip));         
        return substr(preg_replace("/([A-f0-9]{4})/", "$1:", $hex['hex']), 0, -1);
    }

    protected function Read($bytes){
        $data = fread($this->handler, $bytes);
        if($data === false){
            throw new IPNotFoundException("Unknown file format. Please check the file's integrity. EID 13");
        }

        return $data;
    }

    protected function ReadAt($position, $bytes){
        fseek($this->handler, $position);
        $data = fread($this->handler, $bytes);
        if($data === false){
            throw new IPNotFoundException("Unknown file format. Please check the file's integrity. EID 14");
        }

        return $data;
    }

    protected function uVarInt($bytes){
        $x = 0;
        $s = 0;
        for($i = 0;$i<count($bytes);$i++){
            $b = $bytes[$i];
            if($b < 0x80) {
                return $x | $b<<$s;
            }

            $x |= $b&0x7f << $s;
            $s += 7;
        }

        return 0;
    }
}
