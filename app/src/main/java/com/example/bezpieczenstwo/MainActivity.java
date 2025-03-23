package com.example.bezpieczenstwo;

import android.content.Intent;
import android.os.Bundle;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.chip.Chip;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.util.List;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

        private boolean isEncode = true; // Domyślnie ustawione na encode


        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            EdgeToEdge.enable(this);
            setContentView(R.layout.activity_main);

            Spinner algorythmsSpinner = findViewById(R.id.spinner_algorythm);
            Spinner generetedKeySpinner = findViewById(R.id.spinner_AlgKeysLength);
            generetedKeySpinner.setEnabled(false);

            Chip chip = findViewById(R.id.chip);
            chip.setEnabled(false);

            EditText inputEditText = findViewById(R.id.editTextInput);
            EditText outputEditText = findViewById(R.id.TextViewOutput);

            Button sendButton = findViewById(R.id.button_send);
            Button keyButton = findViewById(R.id.button_key);
            sendButton.setEnabled(false);

            //Przekierowanie do strony z kluczami
            keyButton.setOnClickListener(v -> {
                Intent intent = new Intent(MainActivity.this, MagazynKluczyActivity.class);
                startActivity(intent);
            });

            //TODO: zmienić nazwy algorytmów na aliasy które będą sie wyświetlać w spinnerze a magazynowane bądą w KeyStore
            String[] algorythms = {"RSA", "AES"};
            List<String> keyAliasRSA = MagazynKluczyMenager.getKeyAliases().stream().filter(alias -> alias.contains("RSA")).collect(java.util.stream.Collectors.toList());
            List<String> keyAliasAES = MagazynKluczyMenager.getKeyAliases().stream().filter(alias -> alias.contains("AES")).collect(java.util.stream.Collectors.toList());

            ArrayAdapter<String> algorythmsAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, algorythms);
            algorythmsAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            algorythmsSpinner.setAdapter(algorythmsAdapter);

            algorythmsSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                @Override
                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                    // Pobranie wybranego elementu
                    String selectedItem = parent.getItemAtPosition(position).toString();
                    generetedKeySpinner.setEnabled(true);
                    sendButton.setEnabled(true);
                    chip.setEnabled(true);

                    // Wyświetlenie wybranego elementu
                    if (selectedItem.equals(KeyProperties.KEY_ALGORITHM_RSA)) {
                        ArrayAdapter<String> keysAdapter = new ArrayAdapter<>(MainActivity.this, android.R.layout.simple_spinner_item, keyAliasRSA);
                        keysAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
                        generetedKeySpinner.setAdapter(keysAdapter);
                    } else {
                        ArrayAdapter<String> keysAdapter = new ArrayAdapter<>(MainActivity.this, android.R.layout.simple_spinner_item, keyAliasAES);
                        keysAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
                        generetedKeySpinner.setAdapter(keysAdapter);
                    }
                }

                @Override
                public void onNothingSelected(AdapterView<?> adapterView) {
                }
            });

            //przy przełączeniu między szyfrowaniem i deszyfrowaniem
            chip.setOnCheckedChangeListener((buttonView, isChecked) -> {
                isEncode = !isChecked; // Aktualizacja stanu isEncode
                if (isChecked) {
                    chip.setText("Decode");
                } else {
                    chip.setText("Encode");
                }
            });


            sendButton.setOnClickListener(view -> {
                String data = inputEditText.getText().toString();
                String algorythm = algorythmsSpinner.getSelectedItem().toString();
                String selectedKey = generetedKeySpinner.getSelectedItem().toString();

                if (isEncode) {
                    // Kod szyfrowania
                    if (algorythm.equals(KeyProperties.KEY_ALGORITHM_RSA)) {
                        try {
                            PublicKey publicKey = MagazynKluczyMenager.getRSAPublicKey(selectedKey);
                            Toast.makeText(this, "znaleziono klucz publiczny", Toast.LENGTH_SHORT).show();
                            String encryptedMessage = MagazynKluczyMenager.encryptRSA(data, publicKey);
                            Toast.makeText(this, "szyfrowanie zakończone", Toast.LENGTH_SHORT).show();
                            outputEditText.setText(encryptedMessage);
                        } catch (UnrecoverableEntryException | KeyStoreException |
                                 NoSuchAlgorithmException e) {
                            throw new RuntimeException(e);
                        } catch (NoSuchPaddingException e) {
                            throw new RuntimeException(e);
                        }
                    } else {
                        try {
                            SecretKey secretKey = MagazynKluczyMenager.getAESKey(selectedKey);
                            Toast.makeText(this, "znaleziono klucz AES", Toast.LENGTH_SHORT).show();
                            String outputData = MagazynKluczyMenager.encryptAES(data, secretKey);
                            Toast.makeText(this, "szyfrowanie zakończone", Toast.LENGTH_SHORT).show();
                            outputEditText.setText(outputData);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                } else {
                    // Kod deszyfrowania
                    if (algorythm.equals(KeyProperties.KEY_ALGORITHM_RSA)) {
                        try {
                            PrivateKey privateKey = MagazynKluczyMenager.getRSAPrivateKey(selectedKey);
                            Toast.makeText(this, "znaleziono klucz prywatny", Toast.LENGTH_SHORT).show();
                            String decryptedMessage = MagazynKluczyMenager.decryptRSA(data, privateKey);
                            Toast.makeText(this, "deszyfrowanie zakończone", Toast.LENGTH_SHORT).show();
                            outputEditText.setText(decryptedMessage);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    } else {
                        try {
                            SecretKey secretKey = MagazynKluczyMenager.getAESKey(selectedKey);
                            Toast.makeText(this, "znaleziono klucz AES", Toast.LENGTH_SHORT).show();
                            String outputData = MagazynKluczyMenager.decryptAES(data, secretKey);
                            Toast.makeText(this, "deszyfrowanie zakończone", Toast.LENGTH_SHORT).show();
                            outputEditText.setText(outputData);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            });

            ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
                Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
                v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
                return insets;
            });
        }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }
}