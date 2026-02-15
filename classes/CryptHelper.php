<?php namespace Mercator\Totp2faFrontend\Classes;

use Illuminate\Support\Facades\Crypt;

class CryptHelper
{
    public static function encrypt($data)
    {
        return Crypt::encryptString($data);
    }

    public static function decrypt($data)
    {
        try {
            return Crypt::decryptString($data);
        } catch (\Exception $e) {
            return null;
        }
    }

    public static function encryptRecoveryCodes($codes)
    {
        return self::encrypt(json_encode($codes));
    }

    public static function decryptRecoveryCodes($encrypted)
    {
        $json = self::decrypt($encrypted);
        if (!$json) {
            return [];
        }
        return json_decode($json, true) ?? [];
    }

    public static function encryptSecret($secret)
    {
        return self::encrypt($secret);
    }

    public static function decryptSecret($encrypted)
    {
        return self::decrypt($encrypted);
    }
}
