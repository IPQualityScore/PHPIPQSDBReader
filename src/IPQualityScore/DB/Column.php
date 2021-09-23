<?php
namespace IPQualityScore\DB;

class Column {
    private $name;
    private $type;
    private $value;
    public static function Create($name, $type, $value = null){
        $column = new Column();

        $column->Name(trim($name)); // Remove extra null/blank bytes.
        $column->Type($type);
        $column->Value($value);

        return $column;
    }

    public function Name($value = null){
        if($value !== null){
            $this->name = $value;
        }

        return $this->name;
    }

    public function Type(BinaryOption $value = null){
        if($value !== null){
            $this->type = $value;
        }

        return $this->type;
    }

    public function Value($value = null){
        if($value !== null){
            $this->value = $value;
        }

        return $value;
    }
}