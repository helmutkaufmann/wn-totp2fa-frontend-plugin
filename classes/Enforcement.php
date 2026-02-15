<?php namespace Mercator\Totp2faFrontend\Classes;

class Enforcement
{
    public static function is2faEnabled($user)
    {
        return $user && (bool) $user->twofa_enabled;
    }

    public static function isVerifiedForSession($user)
    {
        if (!self::is2faEnabled($user)) {
            return true;
        }
        $verifiedAt = session('mercator.totp2fa.verified_at');
        if (!$verifiedAt) {
            return false;
        }
        $expiry = $verifiedAt + (30 * 24 * 60 * 60);
        return time() < $expiry;
    }

    public static function markVerifiedForSession()
    {
        session(['mercator.totp2fa.verified_at' => time()]);
    }

    public static function clearSessionVerification()
    {
        session()->forget('mercator.totp2fa.verified_at');
    }

    public static function shouldShowRecoveryCodes()
    {
        return session()->has('mercator.totp2fa.show_recovery_codes');
    }

    public static function setShowRecoveryCodes()
    {
        session(['mercator.totp2fa.show_recovery_codes' => true]);
    }

    public static function clearShowRecoveryCodes()
    {
        session()->forget('mercator.totp2fa.show_recovery_codes');
    }

    public static function setIntendedUrl($url)
    {
        session(['mercator.totp2fa.intended' => $url]);
    }

    public static function getIntendedUrl($default = '/')
    {
        return session('mercator.totp2fa.intended', $default);
    }

    public static function clearIntendedUrl()
    {
        session()->forget('mercator.totp2fa.intended');
    }
}
