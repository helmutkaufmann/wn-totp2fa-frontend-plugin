<?php namespace Mercator\Totp2faFrontend\Models;

use Winter\Storm\Database\Model;

class TotpSecret extends Model
{
    public $table = 'totp_secrets';
    public $timestamps = true;
    protected $fillable = ['user_id', 'secret', 'verified_at'];
    protected $dates = ['verified_at', 'created_at', 'updated_at'];
    
    public function user()
    {
        return $this->belongsTo('App\Models\User');
    }
}
