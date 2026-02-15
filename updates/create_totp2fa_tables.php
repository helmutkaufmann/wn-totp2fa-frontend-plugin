<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Schema;

class CreateTotp2faTables extends Migration
{
    public function up()
    {
        Schema::table('users', function ($table) {
            $table->string('totp_secret')->nullable();  // Field to store the TOTP secret
            $table->boolean('totp_enabled')->default(false); // Field to indicate if TOTP is enabled
        });
    }

    public function down()
    {
        Schema::table('users', function ($table) {
            $table->dropColumn(['totp_secret', 'totp_enabled']);
        });
    }
}