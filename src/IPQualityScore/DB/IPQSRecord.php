<?php
namespace IPQualityScore\DB;

class IPQSRecord {
    /**
     * IsProxy - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsProxy($value = null){
        if($value !== null){
            $this->isproxy = $value;
        }

        return $this->isproxy;
    }

    /**
     * IsVPN - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsVPN($value = null){
        if($value !== null){
            $this->isvpn = $value;
        }

        return $this->isvpn;
    }

    /**
     * IsTOR - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsTOR($value = null){
        if($value !== null){
            $this->istor = $value;
        }

        return $this->istor;
    }

    /**
     * IsCrawler - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsCrawler($value = null){
        if($value !== null){
            $this->iscrawler = $value;
        }

        return $this->iscrawler;
    }

    /**
     * IsBot - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsBot($value = null){
        if($value !== null){
            $this->isbot = $value;
        }

        return $this->isbot;
    }

    /**
     * RecentAbuse - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function RecentAbuse($value = null){
        if($value !== null){
            $this->recentabuse = $value;
        }

        return $this->recentabuse;
    }

    /**
     * IsBlacklisted - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsBlacklisted($value = null){
        if($value !== null){
            $this->blacklisted = $value;
        }

        return $this->blacklisted;
    }

    /**
     * IsPrivate - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsPrivate($value = null){
        if($value !== null){
            $this->isprivate = $value;
        }

        return $this->isprivate;
    }

    /**
     * IsMobile - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsMobile($value = null){
        if($value !== null){
            $this->ismobile = $value;
        }

        return $this->ismobile;
    }

    /**
     * HasOpenPorts - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function HasOpenPorts($value = null){
        if($value !== null){
            $this->hasopenports = $value;
        }

        return $this->hasopenports;
    }

    /**
     * IsHostingProvider - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function IsHostingProvider($value = null){
        if($value !== null){
            $this->ishostingprovider = $value;
        }

        return $this->ishostingprovider;
    }

    /**
     * ActiveVPN - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function ActiveVPN($value = null){
        if($value !== null){
            $this->activevpn = $value;
        }

        return $this->activevpn;
    }

    /**
     * ActiveTOR - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function ActiveTOR($value = null){
        if($value !== null){
            $this->activetor = $value;
        }

        return $this->activetor;
    }

    /**
     * PublicAccessPoint - Getter/Setter.
     *
     * @param bool $value, changes held value if $value is not null.
     * @return bool|void
     */
    public function PublicAccessPoint($value = null){
        if($value !== null){
            $this->publicaccesspoint = $value;
        }

        return $this->publicaccesspoint;
    }

    /**
     * ConnectionTypeRaw - Getter/Setter.
     *
     * @param BinaryOption $value, changes held value if $value is not null.
     * @return int|bool
     */
    public function ConnectionTypeRaw(BinaryOption $value = null){
        if($value !== null){
            $this->connectiontype = $this->ConvertConnectionType($value);
        }

        return $this->connectiontype;
    }

    /**
     * ConnectionType - Getter/Setter.
     *
     * @param BinaryOption $value, changes held value if $value is not null.
     * @return string|void
     */
    public function ConnectionType(BinaryOption $value = null){
        if($value !== null){
            $this->connectiontype = $this->ConvertConnectionType($value);
        }

        switch($this->connectiontype){
            case 1:
                return "Residential";
            case 2:
                return "Mobile";
            case 3:
                return "Corporate";
            case 4:
                return "Data Center";
            case 5:
                return "Education";
            default:
                return "Unknown";
        }
    }
        
    /**
     * FraudScore - Getter/Setter.
     *
     * @param  int $strictness
     * @param  int|null $value
     * @return int|void
     */
    public function FraudScore($strictness = 0, $value = null){
        if($value !== null){
            $this->fraudscore[$strictness] = $value;
        }

        return isset($this->fraudscore[$strictness]) ? $this->fraudscore[$strictness] : null;
    }
        
    /**
     * SetFraudScore - Setter.
     *
     * @param int $strictness
     * @param int $value
     * @return void
     */
    public function SetFraudScore($strictness, $value){
        $this->fraudscore[$strictness] = $value;
    }

    /**
     * AbuseVelocityRaw - Getter/Setter.
     *
     * @param BinaryOption $value, changes held value if $value is not null.
     * @return int|void;
     */
    public function AbuseVelocityRaw(BinaryOption $value = null){
        if($value !== null){
            $this->abusevelocity = $value;
        }

        return $this->abusevelocity;
    }

    /**
     * AbuseVelocity - Getter/Setter.
     *
     * @param BinaryOption $value, changes held value if $value is not null.
     * @return string|void
     */
    public function AbuseVelocity(BinaryOption $value = null){
        if($value !== null){
            $this->abusevelocity = $this->ConvertAbuseVelocity($value);
        }

        switch($this->abusevelocity){
            case 1:
                return "low";
            case 2:
                return "medium";
            case 3:
                return "high";
            default:
                return "none";
        }
    }

    /**
     * Country - Getter/Setter.
     *
     * @param string $value, changes held value if $value is not null.
     * @return string|void
     */
    public function Country($value = null){
        if($value !== null){
            $this->country = $value;
        }

        return $this->country;
    }

    /**
     * City - Getter/Setter.
     *
     * @param string $value, changes held value if $value is not null.
     * @return string|void
     */
    public function City($value = null){
        if($value !== null){
            $this->city = $value;
        }
        
        return $this->city;
    }

    /**
     * Region - Getter/Setter.
     *
     * @param string $value, changes held value if $value is not null.
     * @return string|void
     */
    public function Region($value = null){
        if($value !== null){
            $this->region = $value;
        }

        return $this->region;
    }

    /**
     * ISP - Getter/Setter.
     *
     * @param string $value, changes held value if $value is not null.
     * @return string|void
     */
    public function ISP($value = null){
        if($value !== null){
            $this->isp = $value;
        }

        return $this->isp;
    }

    /**
     * Organization - Getter/Setter.
     *
     * @param string $value, changes held value if $value is not null.
     * @return string|void
     */
    public function Organization($value = null){
        if($value !== null){
            $this->organization = $value;
        }

        return $this->organization;
    }

    /**
     * Timezone - Getter/Setter.
     *
     * @param string $value, changes held value if $value is not null.
     * @return string|void
     */
    public function Timezone($value = null){
        if($value !== null){
            $this->timezone = $value;
        }

        return $this->timezone;
    }

    /**
     * Latitude - Getter/Setter.
     *
     * @param float $value, changes held value if $value is not null.
     * @return float|void
     */
    public function Latitude($value = null){
        if($value !== null){
            $this->latitude = $value;
        }

        return $this->latitude;
    }

    /**
     * Longitude - Getter/Setter.
     *
     * @param float $value, changes held value if $value is not null.
     * @return float|void
     */
    public function Longitude($value = null){
        if($value !== null){
            $this->longitude = $value;
        }

        return $this->longitude;
    }

    /**
     * ASN - Getter/Setter.
     *
     * @param int $value, changes held value if $value is not null.
     * @return int|void
     */
    public function ASN($value = null){
        if($value !== null){
            $this->asn = $value;
        }

        return $this->asn;
    }
    
    /**
     * GetColumns
     *
     * @return array of \IPQualityScore\DB\Column
     */
    public function GetColumns(){
        return $this->columns;
    }

    /**
     * Region - Getter/Setter.
     *
     * @param string $value, changes held value if $value is not null.
     * @return string|void
     */
    public function AddColumn(Column $column){
        $this->columns[] = $column;
    }

    /**
     * ParseFirstByte - Parses the first byte of a Record. (Generally intended for internal use).
     *
     * @param BinaryOption $value
     * @return void
     */
    public function ParseFirstByte(BinaryOption $value){
        if($value->Has(BinaryOption::IsProxy)){
            $this->isproxy = true;
        }

        if($value->Has(BinaryOption::IsVPN)){
            $this->isvpn = true;
        }

        if($value->Has(BinaryOption::IsTOR)){
            $this->istor = true;
        }

        if($value->Has(BinaryOption::IsCrawler)){
            $this->iscrawler = true;
        }

        if($value->Has(BinaryOption::IsBot)){
            $this->isbot = true;
        }

        if($value->Has(BinaryOption::RecentAbuse)){
            $this->recentabuse = true;
        }

        if($value->Has(BinaryOption::IsBlacklisted)){
            $this->isblacklisted = true;
        }

        if($value->Has(BinaryOption::IsPrivate)){
            $this->isprivate = true;
        }
    }

    /**
     * ParseSecondByte - Parses the first byte of a Record. (Generally intended for internal use).
     *
     * @param BinaryOption $value
     * @return void
     */
    public function ParseSecondByte(BinaryOption $value){
        if($value->Has(BinaryOption::IsMobile)){
            $this->ismobile = true;
        }

        if($value->Has(BinaryOption::HasOpenPorts)){
            $this->hasopenports = true;
        }

        if($value->Has(BinaryOption::IsHostingProvider)){
            $this->ishostingprovider = true;
        }

        if($value->Has(BinaryOption::ActiveVPN)){
            $this->activevpn = true;
        }

        if($value->Has(BinaryOption::ActiveTOR)){
            $this->activetor = true;
        }

        if($value->Has(BinaryOption::PublicAccessPoint)){
            $this->publicaccesspoint = true;
        }
    }

    protected function ConvertConnectionType(BinaryOption $value){
        if($value->Has(BinaryOption::ConnectionTypeThree)){
            if($value->Has(BinaryOption::ConnectionTypeTwo)){
                return 3;
            }

            if($value->Has(BinaryOption::ConnectionTypeOne)){
                return 5;
            }

            return 1;
        }

        if($value->Has(BinaryOption::ConnectionTypeTwo)){
            return 2;
        }

        if($value->Has(BinaryOption::ConnectionTypeOne)){
            return 4;
        }

        return 0;
    }

    protected function ConvertAbuseVelocity(BinaryOption $value){
        if($value->Has(BinaryOption::AbuseVelocityTwo)){
            if($value->Has(BinaryOption::AbuseVelocityOne)){
                return 3;
            }

            return 1;
        }

        if($value->Has(BinaryOption::AbuseVelocityOne)){
            return 2;
        }

        return 0;
    }

    protected $isproxy = false;
    protected $isvpn = false;
    protected $istor = false;
    protected $iscrawler = false;
    protected $isbot = false;
    protected $recentabuse = false;
    protected $blacklisted = false;
    protected $isprivate = false;

    protected $ismobile = false;
    protected $hasopenports = false;
    protected $ishostingprovider = false;
    protected $activevpn = false;
    protected $activetor = false;
    protected $publicaccesspoint = false;

    protected $connectiontype = -1;
    protected $fraudscore = [];
    protected $abusevelocity = 0;

    protected $country;
    protected $city;
    protected $region;
    protected $isp;
    protected $organization;
    protected $asn;
    protected $timezone;
    protected $latitude;
    protected $longitude;
    protected $columns = [];
}