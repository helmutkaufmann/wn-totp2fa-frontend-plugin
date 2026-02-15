<?php namespace Mercator\Totp2faFrontend\Classes;

use Illuminate\Support\Str;

class RecoveryCodeGenerator
{
    const CODE_COUNT = 10;

    public static function generate($count = self::CODE_COUNT)
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = self::generateSingleCode();
        }
        return $codes;
    }

    protected static function generateSingleCode()
    {
        $part1 = strtoupper(Str::random(4));
        $part2 = strtoupper(Str::random(4));
        return $part1 . '-' . $part2;
    }

    public static function format($code)
    {
        return strtoupper(str_replace(' ', '', $code));
    }

    public static function validate($code)
    {
        $formatted = self::format($code);
        return preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $formatted) === 1;
    }

    public static function codeExists($code, $codes)
    {
        $formatted = self::format($code);
        foreach ($codes as $storedCode) {
            if (self::format($storedCode) === $formatted) {
                return true;
            }
        }
        return false;
    }

    public static function removeCode($code, $codes)
    {
        $formatted = self::format($code);
        $remaining = [];
        foreach ($codes as $storedCode) {
            if (self::format($storedCode) !== $formatted) {
                $remaining[] = $storedCode;
            }
        }
        return $remaining;
    }
}
