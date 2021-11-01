<?php
namespace IPQualityScore\DB;

class BinaryOption {
    private $data;    
    /**
     * SetData - Sets the bitmask.
     *
     * @param int $bit
     * @return void
     */
    public function SetData($bit){
        $this->data = $bit;
    }
    
    /**
     * Has - Checks if the bitmask contains $value.
     *
     * @param int $value
     * @return bool
     */
    public function Has($value){
        return ($this->data & $value);
    }

    /**
     * Set - Modifies the bitmask to add $value to it.
     *
     * @param int $value
     * @return void
     */
    public function Set($value){
        $this->data = $this->data | $value;
    }

    /**
     * Create - Creates a new BinaryOption() using $value
     *
     * @param int $value
     * @return BinaryOption
     */
    public static function Create($value){
        $result = new BinaryOption();
        $result->SetData($value);
        return $result;
    }

    const IPv4Map = 1 << 0;
    const IPv6Map = 1 << 1;
    const BlacklistFile = 1 << 2;
    const BinaryData = 1 << 7;
    
    const TreeData = 1 << 2;
    const StringData = 1 << 3;
    const SmallIntData = 1 << 4;
    const IntData = 1 << 5;
    const FloatData = 1 << 6;

    const IsProxy = 1 << 0;
    const IsVPN = 1 << 1;
    const IsTOR = 1 << 2;
    const IsCrawler = 1 << 3;
    const IsBot = 1 << 4;
    const RecentAbuse = 1 << 5;
    const IsBlacklisted = 1 << 6;
    const IsPrivate = 1 << 7;

    const IsMobile = 1 << 0;
    const HasOpenPorts = 1 << 1;
    const IsHostingProvider = 1 << 2;
    const ActiveVPN = 1 << 3;
    const ActiveTOR = 1 << 4;
    const PublicAccessPoint = 1 << 5;
    const ReservedOne = 1 << 6;
    const ReservedTwo = 1 << 7;

    const ReservedThree = 1 << 0;
    const ReservedFour = 1 << 1;
    const ReservedFive = 1 << 2;
    const ConnectionTypeOne = 1 << 3;
    const ConnectionTypeTwo = 1 << 4;
    const ConnectionTypeThree = 1 << 5;
    const AbuseVelocityOne = 1 << 6;
    const AbuseVelocityTwo = 1 << 7;
}