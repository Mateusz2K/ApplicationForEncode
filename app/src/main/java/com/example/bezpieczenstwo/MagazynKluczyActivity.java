package com.example.bezpieczenstwo;

import android.content.Intent;
import android.os.Bundle;
import android.view.MenuItem;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;


import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Objects;

public class MagazynKluczyActivity extends AppCompatActivity {
    public static final String[] ALGORYTMY = {"RSA", "AES", "Wszystkie"};
    private LinearLayout keyAliasesContainer;
    @Override
    protected void onResume() {
        super.onResume();
        loadKeyAliases(); // Wywołanie loadKeyAliases() w onResume()
    }
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.magazyn_kluczy);
        Button createButton = findViewById(R.id.button_key);
        Spinner spinnerType = findViewById(R.id.spinnerType);
        keyAliasesContainer = findViewById(R.id.conteinerLinear);
        loadKeyAliases();

        ArrayAdapter<String> algorytmu = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, ALGORYTMY);
        algorytmu.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerType.setAdapter(algorytmu);


        createButton.setOnClickListener(view -> {
            Intent intent = new Intent(this, StworzKluczActivity.class);
            startActivity(intent);
        });


        Toolbar upToolbar = findViewById(R.id.my_toolbar);
        setSupportActionBar(upToolbar);
        //TODO: ustawić scroll na aliasy kluczy. Przy naciśnieciu wybiera klucz, przy wciśnieciu opcje, można zarządzać kluczami
        Objects.requireNonNull(getSupportActionBar()).setDisplayHomeAsUpEnabled(true);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
    private void loadKeyAliases() {
        keyAliasesContainer.removeAllViews(); // Usunięcie poprzednich aliasów

        List<String> aliases = MagazynKluczyMenager.getKeyAliases();

        for (String alias : aliases) {
            // Tworzenie LinearLayout dla pojedynczego aliasu i przycisku
            LinearLayout aliasLayout = new LinearLayout(this);
            aliasLayout.setOrientation(LinearLayout.HORIZONTAL);
            LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
            );
            aliasLayout.setLayoutParams(layoutParams);

            // Tworzenie TextView z aliasem
            TextView aliasTextView = new TextView(this);
            aliasTextView.setText(alias);
            LinearLayout.LayoutParams aliasParams = new LinearLayout.LayoutParams(
                    0, // Szerokość 0, aby użyć wagi (weight)
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    1f // Waga 1, aby aliasTextView zajmował większość miejsca
            );
            aliasTextView.setLayoutParams(aliasParams);
            aliasTextView.setPadding(10, 10, 10, 10);
            aliasTextView.setTextColor(ContextCompat.getColor(this,android.R.color.black));
            // Dodanie TextView do LinearLayout
            aliasLayout.addView(aliasTextView);

            // Tworzenie przycisku "Usuń"
            Button deleteButton = new Button(this);
            deleteButton.setText("Usuń");
            //Dodawanie przycisku do Linear Layout
            aliasLayout.addView(deleteButton);

            // Obsługa kliknięcia przycisku "Usuń"
            deleteButton.setOnClickListener(v -> {
                MagazynKluczyMenager.deleteKey(alias);
                Toast.makeText(this, "Usuwanie klucza zakończone", Toast.LENGTH_SHORT).show();
// Usuwanie klucza
                loadKeyAliases(); // Odświeżenie listy aliasów
            });
            // Dodanie LinearLayout z aliasem i przyciskiem do głównego kontenera
            keyAliasesContainer.addView(aliasLayout);
        }
    }


}
