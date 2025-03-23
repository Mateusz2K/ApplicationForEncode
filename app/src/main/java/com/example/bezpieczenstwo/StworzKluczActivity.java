package com.example.bezpieczenstwo;

import android.os.Bundle;
import android.security.keystore.KeyProperties;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;
import java.util.Objects;

public class StworzKluczActivity extends AppCompatActivity {
    private static final List<Integer> RSA_KEY_SIZE = List.of(1024, 2048, 3072, 4096);
    private static final List<Integer> AES_KEY_SIZE = List.of(128, 192, 256);
    private static final String ALIAS = "klucz";
    private static final String[] ALGORITHMS = {KeyProperties.KEY_ALGORITHM_AES, KeyProperties.KEY_ALGORITHM_RSA};


    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.stworz_klucz);

        Spinner spinnerSize = findViewById(R.id.spinnerSize);
        spinnerSize.setEnabled(false);
        Spinner spinnerKey = findViewById(R.id.spinnerType);

        //pasek górny
        Toolbar upToolbar = findViewById(R.id.my_toolbar);
        setSupportActionBar(upToolbar);
        //TODO: ustawić scroll na aliasy kluczy. Przy naciśnieciu wybiera klucz, przy wciśnieciu opcje, można zarządzać kluczami
        Objects.requireNonNull(getSupportActionBar()).setDisplayHomeAsUpEnabled(true);

        Button stworzButton = findViewById(R.id.button_key);
        EditText aliasEditText = findViewById(R.id.editTextAlias);
        stworzButton.setEnabled(false);
        //pokazanie listy algorytmow
        spinnerKey.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, ALGORITHMS));

        //logika spinnera przy wybieraniu algorytmu szyfrowania
        spinnerKey.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
                String selectedItem = adapterView.getItemAtPosition(i).toString();
                if (selectedItem.equals(KeyProperties.KEY_ALGORITHM_AES)) {
                    spinnerSize.setEnabled(true);
                    stworzButton.setEnabled(true);
                    spinnerSize.setAdapter(new ArrayAdapter<>(StworzKluczActivity.this, android.R.layout.simple_spinner_item, AES_KEY_SIZE));
                }
                else {
                    spinnerSize.setEnabled(true);
                    stworzButton.setEnabled(true);
                    spinnerSize.setAdapter(new ArrayAdapter<>(StworzKluczActivity.this, android.R.layout.simple_spinner_item, RSA_KEY_SIZE));
                }
            }
            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {

            }
        });
        //pobranie wybranych danych do stworzeznia
        stworzButton.setOnClickListener(view -> {
            String selectedKey = spinnerKey.getSelectedItem().toString();
            String alias = aliasEditText.getText().toString();
            int selectedSize = (int) spinnerSize.getSelectedItem();
            if (alias.isEmpty()) {
                alias = ALIAS;
            }
            if (selectedKey.equals(KeyProperties.KEY_ALGORITHM_AES)) {
                try {
                    MagazynKluczyMenager.createAESKey(alias, selectedSize);
                    finish();
                    Toast.makeText(this, "Tworzenie klucza AES zakończone", Toast.LENGTH_SHORT).show();

                } catch (KeyStoreException | NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchProviderException e) {
                    throw new RuntimeException(e);
                }
            } else {
                try {
                    MagazynKluczyMenager.createRSAKeyPair(alias,selectedSize);
                    Toast.makeText(this, "Tworzenie klucza RSA zakończone", Toast.LENGTH_SHORT).show();

                    finish();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchProviderException e) {
                    throw new RuntimeException(e);
                } catch (KeyStoreException e) {
                    throw new RuntimeException(e);
                }

            }

        });

    }
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}