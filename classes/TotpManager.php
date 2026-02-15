<?php namespace Mercator\Totp2faFrontend\Classes;

use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

class TotpManager
{
    protected $google2fa;

    public function __construct()
    {
        $this->google2fa = new Google2FA();
    }

    public function generateSecret()
    {
        return $this->google2fa->generateSecretKey();
    }

    public function generateQrCode($secret, $email, $issuer = 'Winter CMS')
    {
        $renderer = new ImageRenderer(new RendererStyle(400));
        $writer = new Writer($renderer);
        $url = $this->google2fa->getQRCodeUrl($issuer, $email, $secret);
        return base64_encode($writer->writeString($url));
    }

    public function verifyCode($secret, $code)
    {
        try {
            return $this->google2fa->verifyKey($secret, $code, 2);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function verifyCodeWithWindow($secret, $code, $window = 1)
    {
        try {
            $timestamp = $this->google2fa->getTimestamp();
            for ($i = -$window; $i <= $window; $i++) {
                $expectedCode = $this->google2fa->totp($secret, $timestamp + ($i * 30));
                if ($code === $expectedCode) {
                    return true;
                }
            }
            return false;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function getCurrentCounter()
    {
        return floor(microtime(true) / 30);
    }
}
