//Mollie Davidson
//Cyber Security
//Dr. Ammari
//PRESENT block cipher

#include <iostream>
using namespace std;

void generateRoundKey(int *K, int *roundkey, int *roundCounter)
{

        for (int j = 0; j < 64; j++)
            roundkey[j] = K[j];
        
    //ROTATION
        for (int count = 61; count > 0; count--)
        {
            //store first Key element data
            int temp = K[0];
            //shift elements left
            for (int i = 1; i < 80; i++)
            {
                K[i-1] = K[i];
            }
            //move first Key element data to last position
            K[79] = temp;
        }
        
    //S-BOX
        int num = 0;
        //calculate decimal value of first 4 Key bits
        if (K[3]==1)
            num+=1;
        if (K[2]==1)
            num+=2;
        if (K[1]==1)
            num+=4;
        if (K[0]==1)
            num+=8;
        
        //sbox update
        
        //0-->C(12)
        if (num==0)
        {
            K[0] = 1;
            K[1] = 1;
            K[2] = 0;
            K[3] = 0;
        }
        //1-->5
        if (num==1)
        {
            K[0] = 0;
            K[1] = 1;
            K[2] = 0;
            K[3] = 1;
        }
        //2-->6
        if (num==2)
        {
            K[0] = 0;
            K[1] = 1;
            K[2] = 1;
            K[3] = 0;
        }
        //3-->B(11)
        if (num==3)
        {
            K[0] = 1;
            K[1] = 0;
            K[2] = 1;
            K[3] = 1;
        }
        //4-->9
        if (num==4)
        {
            K[0] = 1;
            K[1] = 0;
            K[2] = 0;
            K[3] = 1;
        }
        //5-->0
        if (num==5)
        {
            K[0] = 0;
            K[1] = 0;
            K[2] = 0;
            K[3] = 0;
        }
        //6-->A(10)
        if (num==6)
        {
            K[0] = 1;
            K[1] = 0;
            K[2] = 1;
            K[3] = 0;
        }
        //7-->D(13)
        if (num==7)
        {
            K[0] = 1;
            K[1] = 1;
            K[2] = 0;
            K[3] = 1;
        }
        //8-->3
        if (num==8)
        {
            K[0] = 0;
            K[1] = 0;
            K[2] = 1;
            K[3] = 1;
        }
        //9-->E(14)
        if (num==9)
        {
            K[0] = 1;
            K[1] = 1;
            K[2] = 1;
            K[3] = 0;
        }
        //A-->F(15)
        if (num==10)
        {
            K[0] = 1;
            K[1] = 1;
            K[2] = 1;
            K[3] = 1;
        }
        //B-->8
        if (num==11)
        {
            K[0] = 1;
            K[1] = 0;
            K[2] = 0;
            K[3] = 0;
        }
        //C-->4
        if (num==12)
        {
            K[0] = 0;
            K[1] = 1;
            K[2] = 0;
            K[3] = 0;
        }
        //D-->7
        if (num==13)
        {
            K[0] = 0;
            K[1] = 1;
            K[2] = 1;
            K[3] = 1;
        }
        //E-->1
        if (num==14)
        {
            K[0] = 0;
            K[1] = 0;
            K[2] = 0;
            K[3] = 1;
        }
        //F-->2
        if (num==15)
        {
            K[0] = 0;
            K[1] = 0;
            K[2] = 1;
            K[3] = 0;
        }

    //XOR
        for (int i = 0; i < 5; i++)
        {
            K[60+i] = (K[60+i]!=roundCounter[i]);
        }

}
void p_layer(int *state)
{
    //may choose any bit 1-62
    int i = 1;
    //initialize temp out of range
    int temp = -1;
    //initial data
    int data = state[i];
    
    //bit 0, 21, 42, 63 do not move, each bit moves in triangular pairs--> must loop 20(64-4/3) times
    for (int count = 1; count <= 20; count++)
    {
        int current = i;
        for(int j = 0; j < 3; j++)
        {
            //ith bit moved to i/4 position
            if (current % 4 == 0)
            {
                temp = state[current/4];  //store end pos data in temp
                state[current/4] = data;  //move current pos data to end pos
                data = temp;              //end pos data becomes new data
                current/=4;               //end pos becomes new current pos
            }
            //ith bit moved to i/4 + 16 position
            else if (current % 4 == 1)
            {
                temp = state[current/4 + 16];
                state[current/4 + 16] = data;
                data = temp;
                current = current/4 + 16;
            }
            //ith bit moved to i/4 + 32 position
            else if (current % 4 == 2)
            {
                temp = state[current/4 + 32];
                state[current/4 + 32] = data;
                data = temp;
                current = current/4 + 32;
            }
            //ith bit moved to i/4 + 48 position
            else if (current % 4 == 3)
            {
                temp = state[current/4 + 48];
                state[current/4 + 48] = data;
                data = temp;
                current = current/4 + 48;
            }
        }
        //incrementing i to correct next i
        //i increments differently in each range of count
        if (count <= 12)
        {
            if(count == 12)
                i+=7;
            else if(i%4 == 3)
                i+=2;
            else
                i+=1;
        }
        if (count > 12 && count <= 18)
        {
            if(count == 18)
                i+=12;
            else if(i%4 == 3)
                i+=3;
            else
                i+=1;
        }
        if (count > 18)
        {
            i+=4;
        }
    }
}
void s_box_layer(int *state)
{
    int word[4];
    int num = 0;
    
    for (int i = 0; i < 16; i++)
    {
        //64bits to 16 4bit words
        word[0] = state[4*i+3];
        word[1] = state[4*i+2];
        word[2] = state[4*i+1];
        word[3] = state[4*i];
        
        //calculate decimal value of word
        if (word[3]==1)
            num+=1;
        if (word[2]==1)
            num+=2;
        if (word[1]==1)
            num+=4;
        if (word[0]==1)
            num+=8;
        
        //sbox update
        
        //0-->C(12)
        if (num==0)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 1;
            state[4*i+1] = 0;
            state[4*i]   = 0;
        }
        //1-->5
        if (num==1)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 1;
            state[4*i+1] = 0;
            state[4*i]   = 1;
        }
        //2-->6
        if (num==2)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 1;
            state[4*i+1] = 1;
            state[4*i]   = 0;
        }
        //3-->B(11)
        if (num==3)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 0;
            state[4*i+1] = 1;
            state[4*i]   = 1;
        }
        //4-->9
        if (num==4)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 0;
            state[4*i+1] = 0;
            state[4*i]   = 1;
        }
        //5-->0
        if (num==5)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 0;
            state[4*i+1] = 0;
            state[4*i]   = 0;
        }
        //6-->A(10)
        if (num==6)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 0;
            state[4*i+1] = 1;
            state[4*i]   = 0;
        }
        //7-->D(13)
        if (num==7)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 1;
            state[4*i+1] = 0;
            state[4*i]   = 1;
        }
        //8-->3
        if (num==8)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 0;
            state[4*i+1] = 1;
            state[4*i]   = 1;
        }
        //9-->E(14)
        if (num==9)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 1;
            state[4*i+1] = 1;
            state[4*i]   = 0;
        }
        //A-->F(15)
        if (num==10)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 1;
            state[4*i+1] = 1;
            state[4*i]   = 1;
        }
        //B-->8
        if (num==11)
        {
            state[4*i+3] = 1;
            state[4*i+2] = 0;
            state[4*i+1] = 0;
            state[4*i]   = 0;
        }
        //C-->4
        if (num==12)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 1;
            state[4*i+1] = 0;
            state[4*i]   = 0;
        }
        //D-->7
        if (num==13)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 1;
            state[4*i+1] = 1;
            state[4*i]   = 1;
        }
        //E-->1
        if (num==14)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 0;
            state[4*i+1] = 0;
            state[4*i]   = 1;
        }
        //F-->2
        if (num==15)
        {
            state[4*i+3] = 0;
            state[4*i+2] = 0;
            state[4*i+1] = 1;
            state[4*i]   = 0;
        }
    }
}
void data_xor_key(int *roundKey, int *state)
{
    for (int i = 0; i < 64; i++)
        state[i] = (roundKey[i]!=state[i]);
}
void incrementCounter(int *roundCounter)
{
    int i = 4;
    while (roundCounter[i] != 0)
    {
        while(roundCounter[i] == 1)
        {
            roundCounter[i] = 0;
            i--;
        }
    }
    roundCounter[i] = 1;
}
int main()
{
    //64bit plaintext block as array of int
    int plaintext[64] = {1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
                        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0};
    
    //80bit key as array of int
    int K[80] = {1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0, 1,1,1,1,1,1,1,1,
                1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
                1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1};
    
    //stores current round key
    int roundkey[64];
    
    //round counter as int array
    int roundCounter[5] = {0,0,0,0,0};
    
    //original data
    cout << "UNCIPHERED PLAINTEXT: " << endl;
    for (int i = 0; i < 64; i++)
    {
        cout << plaintext[i];
        if (i%8 == 7 && i != 0)
            cout << endl;
        else if(i%4 == 3 && i != 0)
            cout << " ";
    }
    cout << endl;
    
    //original Key
    cout << "KEY: " << endl;
    for (int i = 0; i < 80; i++)
    {
        cout << K[i];
        if (i%8 == 7 && i != 0)
            cout << endl;
        else if(i%4 == 3 && i != 0)
            cout << " ";
    }
    cout << endl;
    
    for (int i = 0; i < 32; i++)
    {
        generateRoundKey(K, roundkey, roundCounter);
        data_xor_key(roundkey, plaintext);
        s_box_layer(plaintext);
        p_layer(plaintext);
        incrementCounter(roundCounter);
    }
    //final XOR
    data_xor_key(roundkey, plaintext);
    
    //encrypted data
    cout << "ENCIPHERED PLAINTEXT: " << endl;
    for (int i = 0; i < 64; i++)
    {
        cout << plaintext[i];
        if (i%8 == 7 && i != 0)
            cout << endl;
        else if(i%4 == 3 && i != 0)
            cout << " ";
    }
    
    cout << endl << endl;
    
    return 0;
}
