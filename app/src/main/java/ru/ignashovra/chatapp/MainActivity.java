package ru.ignashovra.chatapp;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.firebase.ui.auth.AuthUI;
import com.firebase.ui.database.FirebaseListAdapter;
import com.github.library.bubbleview.BubbleTextView;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.database.FirebaseDatabase;
import android.text.format.DateFormat;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import hani.momanii.supernova_emoji_library.Actions.EmojIconActions;


public class MainActivity extends AppCompatActivity {

    private static int SIGN_IN_CODE = 1;
    private RelativeLayout activity_main;
    private FirebaseListAdapter <Message> adapter;
    private FloatingActionButton seendBtn;



    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if(requestCode == SIGN_IN_CODE) {
            if(requestCode == RESULT_OK){
                Snackbar.make(activity_main, "Вы аторизованы", Snackbar.LENGTH_LONG).show();
                displayAllMessages();
            } else {
                Snackbar.make(activity_main, "Вы не аторизованы", Snackbar.LENGTH_LONG).show();
                finish();
            }
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Secret.kes();



        activity_main = findViewById(R.id.activity_main);
        seendBtn = findViewById(R.id.btnSend);
        seendBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                EditText editText = findViewById(R.id.messageField);
                byte[] textField = Secret.getEncode(editText.getText().toString().getBytes());

                if (textField.toString() == "")
                    return;

                FirebaseDatabase.getInstance().getReference().push().setValue(
                        new Message(
                                FirebaseAuth.getInstance().getCurrentUser().getEmail(),
                                Base64.encodeToString(textField, Base64.DEFAULT)
                        )
                );
                System.out.println("Текст " + textField + ", Закодированные байты" + Base64.encodeToString(textField, Base64.DEFAULT));
                editText.setText("");
            }
        });

        // Пользаватель еще не авторизован
        if(FirebaseAuth.getInstance().getCurrentUser() == null)
            startActivityForResult(AuthUI.getInstance().createSignInIntentBuilder().build(), SIGN_IN_CODE);
        else {
            Snackbar.make(activity_main, "Вы аторизованы", Snackbar.LENGTH_LONG).show();
            displayAllMessages();
        }
    }

    private void displayAllMessages() {
        ListView listOfMessages = findViewById(R.id.list_of_messages);



        adapter = new FirebaseListAdapter<Message>(this, Message.class, R.layout.list_item, FirebaseDatabase.getInstance().getReference()) {
            @Override
            protected void populateView(View v, Message model, int position) {
                TextView mess_user, mess_time;
                BubbleTextView mess_text;



                mess_user = v.findViewById(R.id.message_user);
                mess_time = v.findViewById(R.id.message_time);
                mess_text = v.findViewById(R.id.message_text);

                mess_user.setText(model.getUserName());
                System.out.println("Раскодированные байты" + Base64.decode(model.getTextMessage(), Base64.DEFAULT));
                mess_text.setText(new String( Secret.getDecode(Base64.decode(model.getTextMessage(), Base64.DEFAULT))));
                mess_time.setText(DateFormat.format("dd.MM.yyyy HH:mm:ss",model.getMessageTime()));
            }
        };
        listOfMessages.setAdapter(adapter);
    }
}