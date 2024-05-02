#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cmath>
#include <opencv2/core.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/opencv.hpp>
#include "aes.h"
#include "filters.h"
#include "base64.h"
#include "modes.h"
#include "osrng.h"
using namespace cv;
using namespace std;
using namespace CryptoPP;
// Global variables for key and IV
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
SecByteBlock iv(AES::BLOCKSIZE);
void image_comparison_show(    const Mat& image1   ,    const Mat& image2    ,     const string& title);
void performEncryption( const Mat& image );
void performDecryption();
// ----------------------------------------- test omar jabari code -----------------------------------------------------
vector<unsigned char> mat_into_vector(const Mat& image) {
    vector<unsigned char> data;
    if (image.isContinuous()) {
        data.assign(image.data, image.data + image.total() * image.elemSize());
    }
    else {
        for (int i = 0; i < image.rows; ++i) {
            data.insert(data.end(), image.ptr<unsigned char>(i), image.ptr<unsigned char>(i) + image.cols * image.channels());
        }
    }
    return data;
}
Mat vector_into_mat(const vector<unsigned char>& data, const Size& size, int type) {
    Mat image(size, type);
    if (image.isContinuous()) {
        memcpy(image.data, data.data(), data.size());
    }
    else {
        for (int i = 0; i < image.rows; ++i) {
            memcpy(image.ptr<unsigned char>(i), &data[i * image.cols * image.channels()], image.cols * image.channels());
        }
    }
    return image;
}
vector<unsigned char> encrypt_data(const vector<unsigned char>& data, size_t& encryptedSize) {
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);

    string plainText(data.begin(), data.end());

    string cipherText;
    StringSource(plainText, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(cipherText)
        )
    );
    encryptedSize = cipherText.size();
    return vector<unsigned char>(cipherText.begin(), cipherText.end());
}
vector<unsigned char> decryptData(const vector<unsigned char>& encryptedData) {
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);
    string decryptedText;
    StringSource s(encryptedData.data(), encryptedData.size(), true,
        new StreamTransformationFilter(decryptor,
            new StringSink(decryptedText)
        )
    );
    return vector<unsigned char>(decryptedText.begin(), decryptedText.end());
}
double NPCR_test(const Mat& Encrypted_Image_1, const Mat& Encrypted_Image_2) {
    int totalPixels = Encrypted_Image_1.rows * Encrypted_Image_1.cols * Encrypted_Image_1.channels();
    int differentPixels = 0;
    for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
        for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
            for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                if (Encrypted_Image_1.at<Vec3b>(i, j)[k] != Encrypted_Image_2.at<Vec3b>(i, j)[k]) {
                    ++differentPixels;
                }
            }
        }
    }
    double npc_result = (static_cast<double>(differentPixels) / totalPixels) * 100.0;
    return npc_result;
}
double UACI_TEST(const Mat& Encrypted_Image_1, const Mat& Encrypted_Image_2) {
    int totalPixels = Encrypted_Image_1.rows * Encrypted_Image_1.cols * Encrypted_Image_1.channels();
    double sumDiff = 0.0;
    for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
        for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
            for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                sumDiff += abs(Encrypted_Image_1.at<Vec3b>(i, j)[k] - Encrypted_Image_2.at<Vec3b>(i, j)[k]);
            }
        }
    }
    double uaci = (sumDiff / (totalPixels * 255.0)) * 100.0;
    return uaci;
}
double HD_TEST(const Mat& Encrypted_Image_1, const Mat& Encrypted_Image_2) {
    int totalBits = Encrypted_Image_1.rows * Encrypted_Image_1.cols * Encrypted_Image_1.channels() * 8;
    int hammingDistance = 0;
    for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
        for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
            for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                for (int l = 0; l < 8; ++l) {
                    if (((Encrypted_Image_1.at<Vec3b>(i, j)[k] ^ Encrypted_Image_2.at<Vec3b>(i, j)[k]) >> l) & 1)
                        ++hammingDistance;
                }
            }
        }
    }
    double hd = (static_cast<double>(hammingDistance) / totalBits) * 100.0;
    return hd;
}
double Chi_Square_TEST(const Mat& Encrypted_Image_1, const Mat& Encrypted_Image_2) {
    double chiSquared = 0.0;
    vector<int> observed(256, 0);
    vector<int> expected(256, 0);
    for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
        for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
            for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                observed[Encrypted_Image_1.at<Vec3b>(i, j)[k]]++;
                expected[Encrypted_Image_2.at<Vec3b>(i, j)[k]]++;
            }
        }
    }
    for (int i = 0; i < 256; ++i) {
        chiSquared += pow(observed[i] - expected[i], 2) / expected[i];
    }
    return chiSquared;
}
double Chi_Squared_Histogram(const Mat& encryptedImage) {
    double chiSquared = 0.0;
    vector<int> observed(256, 0);
    for (int i = 0; i < encryptedImage.rows; ++i) {
        for (int j = 0; j < encryptedImage.cols; ++j) {
            for (int k = 0; k < encryptedImage.channels(); ++k) {
                observed[encryptedImage.at<Vec3b>(i, j)[k]]++;
            }
        }
    }
    double expectedFrequency = static_cast<double>(encryptedImage.rows * encryptedImage.cols * encryptedImage.channels()) / 256.0;
    for (int i = 0; i < 256; ++i) {
        chiSquared += pow(observed[i] - expectedFrequency, 2) / expectedFrequency;
    }
    return chiSquared;
}
double InformationEnrtopy_TEST(const Mat& encryptedImage) {
    vector<int> histogram(256, 0);
    // show histogram and calcualte
    for (int i = 0; i < encryptedImage.rows; ++i) {
        for (int j = 0; j < encryptedImage.cols; ++j) {
            for (int k = 0; k < encryptedImage.channels(); ++k) {
                histogram[encryptedImage.at<Vec3b>(i, j)[k]]++;
            }
        }
    }
    //find  entropy
    double entropy = 0.0;
    double totalPixels = encryptedImage.rows * encryptedImage.cols * encryptedImage.channels();
    for (int i = 0; i < 256; ++i) {
        if (histogram[i] > 0) {
            double probability = static_cast<double>(histogram[i]) / totalPixels;
            entropy += probability * log2(1 / probability);
        }
    }
    return entropy;
}
void Histogram_Visualization(const Mat& encryptedImage) {
    // Blue green red
    vector<Mat> bgr_planes;
    split(encryptedImage, bgr_planes);
    int histSize = 256;
    float range[] = { 0, 256 };
    const float* histRange = { range };
    bool uniform = true;
    bool accumulate = false;
    Mat b_hist, g_hist, r_hist;
    // the histogram 
    calcHist(&bgr_planes[0], 1, 0, Mat(), b_hist, 1, &histSize, &histRange, uniform, accumulate);
    calcHist(&bgr_planes[1], 1, 0, Mat(), g_hist, 1, &histSize, &histRange, uniform, accumulate);
    calcHist(&bgr_planes[2], 1, 0, Mat(), r_hist, 1, &histSize, &histRange, uniform, accumulate);
    int hist_w = 512;
    int hist_h = 400;
    int bin_w = cvRound((double)hist_w / histSize);
    Mat histImage(hist_h, hist_w, CV_8UC3, Scalar(0, 0, 0));
    normalize(b_hist, b_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
    normalize(g_hist, g_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
    normalize(r_hist, r_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
    //each channel .........................
    for (int i = 1; i < histSize; i++)
    {
        line(histImage, Point(bin_w * (i - 1), hist_h - cvRound(b_hist.at<float>(i - 1))),
            Point(bin_w * (i), hist_h - cvRound(b_hist.at<float>(i))),
            Scalar(255, 0, 0), 2, 8, 0);
        line(histImage, Point(bin_w * (i - 1), hist_h - cvRound(g_hist.at<float>(i - 1))),
            Point(bin_w * (i), hist_h - cvRound(g_hist.at<float>(i))),
            Scalar(0, 255, 0), 2, 8, 0);
        line(histImage, Point(bin_w * (i - 1), hist_h - cvRound(r_hist.at<float>(i - 1))),
            Point(bin_w * (i), hist_h - cvRound(r_hist.at<float>(i))),
            Scalar(0, 0, 255), 2, 8, 0);
    }
    // Display as an image
    namedWindow("Histogram", WINDOW_AUTOSIZE);
    imshow("Histogram", histImage);
    waitKey(0);
}
double encryption_quality_TEST(const Mat& plainImage, const Mat& encryptedImage) {
    int totalBytes = 256;
    double sumDiff = 0.0;
    vector<int> observedPlain(256, 0);
    for (int i = 0; i < plainImage.rows; ++i) {
        for (int j = 0; j < plainImage.cols; ++j) {
            for (int k = 0; k < plainImage.channels(); ++k) {
                observedPlain[plainImage.at<Vec3b>(i, j)[k]]++;
            }
        }
    }
    vector<int> observedEncrypted(256, 0);
    for (int i = 0; i < encryptedImage.rows; ++i) {
        for (int j = 0; j < encryptedImage.cols; ++j) {
            for (int k = 0; k < encryptedImage.channels(); ++k) {
                observedEncrypted[encryptedImage.at<Vec3b>(i, j)[k]]++;
            }
        }
    }
    for (int i = 0; i < 256; ++i) {
        sumDiff += abs(observedPlain[i] - observedEncrypted[i]);
    }
    double encryption_quality_ = sumDiff / totalBytes;
    return encryption_quality_;
}
void Information_Hiding(Mat& stegoImage, const string& name, int number) {
    string nameBinary = "01101111 01101101 01100001 01110010 01011111 01101010 01100001 01100010 01100001 01110010 01101001"; //  the hiding info name "omar_jabari" in binary
    string idBinary = "00110010 00110001 00110001 00110001 00110100 00110001 00110001 00110000 00110001 00110100 00110000"; //  hiding id in the image "21114411014" in binary
    string confidentialInfoBinary = nameBinary + " " + idBinary;
    int totalBits = confidentialInfoBinary.size();
    Mat flatStegoImage = stegoImage.reshape(1, 1);
    int totalPixels = flatStegoImage.cols;
    for (int i = 0; i < totalBits; ++i) {
        char bit = confidentialInfoBinary[i];
        int pixelIndex = i * 3;
        uchar& intensity = flatStegoImage.at<uchar>(pixelIndex);
        intensity = (intensity & 0xFE) | (bit - '0');
        if (i >= totalBits) {
            break;
        }
    }
    stegoImage = flatStegoImage.reshape(3, stegoImage.rows);
}
int main() {
    cout << "Our Tasks ! " << endl;
    cout << "Choice1:" << " " << "Encryption...Images" << endl;
    cout << "Choice2:" << " " << "NPCR_TEST !" << endl;
    cout << "Choice3:" << " " << "UACI_TEST !" << endl;
    cout << "Choice4:" << " " << "HD_TEST !" << endl;
    cout << "Choice5:" << " " << "Chi_Squared_TESt !" << endl;
    cout << "Choice6:" << " " << "Show ... ChiSquared_Histogram ! && Histogram_Analysis ! && Theoretical_Chi-squared_Value !" << endl;
    cout << "Choice7:" << " " << "Information Entropy:!" << endl;
    cout << "Choice8:" << " " << "Encryption Quality:" << endl;
    cout << "Choice9:" << " " << "Encryption_Time:" << endl;
    cout << "Choice10:" << " " << "SteaganoGraphy image ..  :" << endl;
    cout << "Choice11:" << " " << "Quit :" << endl;
    cout << "(Encryption  & SteganoGraphy ) System .. !" << endl;
    // key and iv 
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    Mat image = imread("C:\\Users\\omarj\\OneDrive\\Documents\\project-photos\\LenaRGB.jpg"); 
    if (image.empty()) {
        cout << "Couldn't find the image .. " << endl;
        return -1;
    }
    Mat image2 = image.clone();
    
    image2.at<Vec3b>(0, 0)[0] ^= 0x01; // change first bit of image 2  ... 
    //-------------------------------------------------------------------------------------------------------------------------------//
    vector<unsigned char> imageData1 = mat_into_vector(image);
    vector<unsigned char> imageData2 = mat_into_vector(image2);
    auto start = chrono::high_resolution_clock::now();
    size_t encryptedSize1, encryptedSize2;
    vector<unsigned char> encrypted_data_1 = encrypt_data(imageData1, encryptedSize1);
    vector<unsigned char> encrypted_data_2 = encrypt_data(imageData2, encryptedSize2);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;

    Mat Encrypted_Image_1 = vector_into_mat(encrypted_data_1, image.size(), image.type());
    Mat Encrypted_Image_2 = vector_into_mat(encrypted_data_2, image2.size(), image2.type());


    Mat stegoImage = image.clone();

    string name = "omar_jabari"; // name i wanna to hide
    int number = 211144; // id i wanna to hide
    Information_Hiding(stegoImage, name, number);

    //the stego image ... 
    imwrite("Stegoimage.bmp", stegoImage); //as_BMP
    cout << "Stegoimage.bmp saved successfully!" << endl;

    bool flag = true;
    while (flag) {
        int choice;
        cout << "Enter choice between  --_ 1 and 11 _ --: ";
        cin >> choice;

        if (choice == 1) {
            imshow("Encrypted image 1", Encrypted_Image_1);
            imshow("Encrypted image 2", Encrypted_Image_2);
            imwrite("Encrypted_image1.bmp", Encrypted_Image_1); //as_BMP
            imwrite("Encrypted_image2.bmp", Encrypted_Image_2); //as_BMP
            waitKey(0);
        }
        else if (choice == 2) {
            double npc_result = NPCR_test(Encrypted_Image_1, Encrypted_Image_2);
            cout << "NPCR (Number of Pixel Change Rate): " << fixed << setprecision(2) << npc_result << "%" << endl;
        }
        else if (choice == 3) {
            double uaci = UACI_TEST(Encrypted_Image_1, Encrypted_Image_2);
            cout << "UACI (Unified Average Change Intensity): " << fixed << setprecision(2) << uaci << "%" << endl;

        }
        else if (choice == 4) {
            double hd = HD_TEST(Encrypted_Image_1, Encrypted_Image_2);
            cout << "HD (Hamming Distance): " << fixed << setprecision(2) << hd << "%" << endl;
        }
        else if (choice==5) {
            double chiSquared = Chi_Square_TEST(Encrypted_Image_1, Encrypted_Image_2);
            cout << "Chi_Square_Result: " << chiSquared << endl;
        }
        else if (choice ==  6) {
            double chi_squared_theoretical = 293.0; // given_value
            double Histogram_chi_squared = Chi_Squared_Histogram(Encrypted_Image_1);
            cout << "Histogram Chi_squared Result: " << Histogram_chi_squared << endl;
            cout << "Theoretical Chi_squared Result: " << chi_squared_theoretical << endl;
            cout << "Histogram Analysis Result: ";
            if (Histogram_chi_squared < chi_squared_theoretical) {
                cout << "Passed." << endl;
            }
            else {
                cout << "Failed." << endl;
            }
            Histogram_Visualization(Encrypted_Image_1); // visualize 
        }
        else if (choice ==7) {
            double information_entropy_= InformationEnrtopy_TEST(Encrypted_Image_1);
            cout << "Information Entropy: " << information_entropy_ << endl;
        }
        else if (choice ==  8) {
            double encryption_quality_ =   encryption_quality_TEST(image, Encrypted_Image_1);
            cout << "Encryption Quality: " << fixed << setprecision(2) << encryption_quality_ << endl;
        }
        else if (choice == 9) {
            double encryption_time_measure =  duration.count();
            cout << "Encryption Time: "<< fixed << setprecision(5) <<encryption_time_measure << " seconds" << endl;
            cout << " Encryption Time in NCPB  Can't be done in this  easy  , some addition tests and hardware needs to measure first ." << endl;
           
        }
        else if (choice == 10) {
            imshow("StegoImage",stegoImage);
            waitKey(0);
        }
        else if (choice == 11) {
           
            flag = false;
        }
        else {
            cout << "Inavlid ,, please choose a number betwee 1 and 11 . " << endl;
        }
    }
    return 0;
}
//----------------------------------------------------------------------------------------------------------------------------------//
