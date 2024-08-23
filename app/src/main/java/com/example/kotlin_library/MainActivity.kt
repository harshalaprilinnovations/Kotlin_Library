package com.example.kotlin_library

import android.os.Bundle
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val securityData = SecurityLibrary.collectSecurityData(this)

        // Convert the data to JSON
        val jsonData = JSONObject(securityData).toString()

        Log.d("JSON_Data_to_be_Sent_Over_Serer" ,"data : $jsonData")
    }
}