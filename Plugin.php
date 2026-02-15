<?php namespace Mercator\Totp2faFrontend;

use System\Classes\PluginBase;
use Auth;
use Event;

class Plugin extends PluginBase
{
    public function pluginDetails()
    {
        return [
            'name'        => 'Frontend TOTP 2FA',
            'description' => 'TOTP-based 2FA for Winter CMS frontend users with one-time recovery code display.',
            'author'      => 'Mercator',
            'icon'        => 'icon-lock',
        ];
    }

    public function boot()
    {
        // Register routes for frontend 2FA
        \Route::group(['middleware' => ['web']], function () {
            // Setup routes - authenticated users only
            \Route::middleware('auth')->group(function () {
                \Route::get('/frontend/totp2fa/setup', 'Mercator\Totp2faFrontend\Controllers\FrontendTotp2faController@setup')->name('totp2fa.setup');
                \Route::post('/frontend/totp2fa/setup', 'Mercator\Totp2faFrontend\Controllers\FrontendTotp2faController@storeSetup')->name('totp2fa.store');
                \Route::get('/frontend/totp2fa/recovery', 'Mercator\Totp2faFrontend\Controllers\FrontendTotp2faController@recovery')->name('totp2fa.recovery');
                \Route::post('/frontend/totp2fa/recovery/acknowledge', 'Mercator\Totp2faFrontend\Controllers\FrontendTotp2faController@acknowledgeRecovery')->name('totp2fa.recovery.acknowledge');
                \Route::get('/frontend/totp2fa/manage', 'Mercator\Totp2faFrontend\Controllers\FrontendTotp2faController@manage')->name('totp2fa.manage');
                \Route::post('/frontend/totp2fa/regenerate', 'Mercator\Totp2faFrontend\Controllers\FrontendTotp2faController@regenerate')->name('totp2fa.regenerate');
                \Route::post('/frontend/totp2fa/disable', 'Mercator\Totp2faFrontend\Controllers\FrontendTotp2faController@disable')->name('totp2fa.disable');
            });

            // Login 2FA challenge - after initial auth but before full session
            \Route::get('/auth/totp2fa-challenge', 'Mercator\Totp2faFrontend\Controllers\LoginTotp2faController@challenge')->name('totp2fa.challenge');
            \Route::post('/auth/totp2fa-challenge', 'Mercator\Totp2faFrontend\Controllers\LoginTotp2faController@verify')->name('totp2fa.verify');
        });
    }
}