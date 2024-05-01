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
vector<unsigned char> matToVector(const Mat& image);
Mat vectorToMat(const vector<unsigned char>& data, const Size& size, int type);
vector<unsigned char> encryptData(const vector<unsigned char>& data, size_t& encryptedSize);
vector<unsigned char> decryptData(const vector<unsigned char>& encryptedData);
double calculateNPCR(const Mat& encryptedImage1, const Mat& encryptedImage2);
double calculateUACI(const Mat& encryptedImage1, const Mat& encryptedImage2);
double calculateHD(const Mat& encryptedImage1, const Mat& encryptedImage2);
double calculateChiSquared(const Mat& encryptedImage1, const Mat& encryptedImage2);
double calculateHistogramChiSquared(const Mat& encryptedImage);
double calculateInformationEntropy(const Mat& encryptedImage);
double calculateEncryptionQuality(const Mat& plainImage, const Mat& encryptedImage);
void visualizeHistogram(const Mat& encryptedImage);
void hideConfidentialInformation(Mat& stegoImage, const string& name, int number);
void displayImageComparison(const Mat& image1, const Mat& image2, const string& title);
void performEncryption(const Mat& image);
void performDecryption();
int main() {
    cout << "Our Tasks ! " << "\n";
    cout << "Choice1:" << " " << "Encryption Images" << "\n";
    cout << "Choice2:" << " " << "Calculate NPCR TEST !" << "\n";
    cout << "Choice3:" << " " << "Calculate UACI TEST !" << "\n";
    cout << "Choice4:" << " " << "Calculate HD TEST !" << "\n";
    cout << "Choice5:" << " " << "Calculate Chi-squared Statistic !" << "\n";
    cout << "Choice6:" << " " << "Calculate Histogram Chi-squared Statistic ! && Histogram Analysis Result ! &&Theoretical Chi-squared Value " << "\n";
    cout << "Choice7:" << " " << "Information Entropy:!" << "\n";
    cout << "Choice8:" << " " << "Encryption Quality:" << "\n";
    cout << "Choice9:" << " " << "Encryption Time:" << "\n";
    cout << "Choice10:" << " " << "SteaganoGraphy image :" << "\n";
    cout << "Choice11:" << " " << "Exit :" << "\n";
    cout << "Initializing Encryption and Steganography System" << endl;
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
    // Change one bit in image2
    image2.at<Vec3b>(0, 0)[0] ^= 0x01; // change first bit 
    //-------------------------------------------------------------------------------------------------------------------------------//
    vector<unsigned char> imageData1 = matToVector(image);
    vector<unsigned char> imageData2 = matToVector(image2);
    auto start = chrono::high_resolution_clock::now();
    size_t encryptedSize1, encryptedSize2;
    vector<unsigned char> encryptedData1 = encryptData(imageData1, encryptedSize1);
    vector<unsigned char> encryptedData2 = encryptData(imageData2, encryptedSize2);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;

    Mat encryptedImage1 = vectorToMat(encryptedData1, image.size(), image.type());
    Mat encryptedImage2 = vectorToMat(encryptedData2, image2.size(), image2.type());


    Mat stegoImage = image.clone();

    string name = "omar_jabari"; // name i wanna to hide
    int number = 211144; // id i wanna to hide
    hideConfidentialInformation(stegoImage, name, number);

    //the stego image ... 
    imwrite("Stegoimage.bmp", stegoImage); //as_BMP
    cout << "Stegoimage.bmp saved successfully!" << endl;

    bool flag = true;
    while (flag) {
        int choice;
        cout << "Enter choice between (1-11): ";
        cin >> choice;

        if (choice == 1) {
            imshow("Encrypted image 1", encryptedImage1);
            imshow("Encrypted image 2", encryptedImage2);
            imwrite("Encrypted_image1.bmp", encryptedImage1); //as_BMP
            imwrite("Encrypted_image2.bmp", encryptedImage2); //as_BMP
            waitKey(0);
        }
        else if (choice == 2) {
            double npcRate = calculateNPCR(encryptedImage1, encryptedImage2);
            cout << "NPCR (Number of Pixel Change Rate): " << fixed << setprecision(2) << npcRate << "%" << endl;
        }
        else if (choice == 3) {
            double uaci = calculateUACI(encryptedImage1, encryptedImage2);
            cout << "UACI (Unified Average Change Intensity): " << fixed << setprecision(2) << uaci << "%" << endl;

        }
        else if (choice == 4) {
            double hd = calculateHD(encryptedImage1, encryptedImage2);
            cout << "HD (Hamming Distance): " << fixed << setprecision(2) << hd << "%" << endl;
        }
        else if (choice == 5) {
            double chiSquared = calculateChiSquared(encryptedImage1, encryptedImage2);
            cout << "Chi-squared Statistic: " << chiSquared << endl;
        }
        else if (choice == 6) {
            double theoreticalChiSquared = 293.0; // Theoretical chi-squared value
            double histogramChiSquared = calculateHistogramChiSquared(encryptedImage1);
            cout << "Histogram Chi-squared Statistic: " << histogramChiSquared << endl;
            cout << "Theoretical Chi-squared Value: " << theoreticalChiSquared << endl;
            cout << "Histogram Analysis Result: ";
            if (histogramChiSquared < theoreticalChiSquared) {
                cout << "Passed (Experimental chi-squared value is less than theoretical chi-squared value)." << endl;
            }
            else {
                cout << "Failed (Experimental chi-squared value is greater than theoretical chi-squared value)." << endl;
            }
            visualizeHistogram(encryptedImage1); // visualize 
        }
        else if (choice == 7) {
            double informationEntropy = calculateInformationEntropy(encryptedImage1);
            cout << "Information Entropy: " << informationEntropy << endl;
        }
        else if (choice == 8) {
            double encryptionQuality = calculateEncryptionQuality(image, encryptedImage1);
            cout << "Encryption Quality: " << fixed << setprecision(2) << encryptionQuality << endl;
        }
        else if (choice == 9) {
            double encryptionTimeInSeconds = duration.count();
            cout << "Encryption Time: " << fixed << setprecision(5) << encryptionTimeInSeconds << " seconds" << endl;
        }
        else if (choice == 10) {
            imshow("StegoImage", stegoImage);
            waitKey(0);
        }
        else if (choice == 11) {
            // Exit
            flag = false;
        }
        else {
            cout << "Inavlid ,, please choose a number betwee 1 and 11 . " << endl;
        }
    }
    return 0;
}
//----------------------------------------------------------------------------------------------------------------------------------//
vector<unsigned char> matToVector(const Mat& image) {
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
Mat vectorToMat(const vector<unsigned char>& data, const Size& size, int type) {
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
vector<unsigned char> encryptData(const vector<unsigned char>& data, size_t& encryptedSize) {
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
double calculateNPCR(const Mat& encryptedImage1, const Mat& encryptedImage2) {
    int totalPixels = encryptedImage1.rows * encryptedImage1.cols * encryptedImage1.channels();
    int differentPixels = 0;
    for (int i = 0; i < encryptedImage1.rows; ++i) {
        for (int j = 0; j < encryptedImage1.cols; ++j) {
            for (int k = 0; k < encryptedImage1.channels(); ++k) {
                if (encryptedImage1.at<Vec3b>(i, j)[k] != encryptedImage2.at<Vec3b>(i, j)[k]) {
                    ++differentPixels;
                }
            }
        }
    }
    double npcRate = (static_cast<double>(differentPixels) / totalPixels) * 100.0;
    return npcRate;
}
double calculateUACI(const Mat& encryptedImage1, const Mat& encryptedImage2) {
    int totalPixels = encryptedImage1.rows * encryptedImage1.cols * encryptedImage1.channels();
    double sumDiff = 0.0;
    for (int i = 0; i < encryptedImage1.rows; ++i) {
        for (int j = 0; j < encryptedImage1.cols; ++j) {
            for (int k = 0; k < encryptedImage1.channels(); ++k) {
                sumDiff += abs(encryptedImage1.at<Vec3b>(i, j)[k] - encryptedImage2.at<Vec3b>(i, j)[k]);
            }
        }
    }
    double uaci = (sumDiff / (totalPixels * 255.0)) * 100.0;
    return uaci;
}
double calculateHD(const Mat& encryptedImage1, const Mat& encryptedImage2) {
    int totalBits = encryptedImage1.rows * encryptedImage1.cols * encryptedImage1.channels() * 8;
    int hammingDistance = 0;
    for (int i = 0; i < encryptedImage1.rows; ++i) {
        for (int j = 0; j < encryptedImage1.cols; ++j) {
            for (int k = 0; k < encryptedImage1.channels(); ++k) {
                for (int l = 0; l < 8; ++l) {
                    if (((encryptedImage1.at<Vec3b>(i, j)[k] ^ encryptedImage2.at<Vec3b>(i, j)[k]) >> l) & 1)
                        ++hammingDistance;
                }
            }
        }
    }
    double hd = (static_cast<double>(hammingDistance) / totalBits) * 100.0;
    return hd;
}
double calculateChiSquared(const Mat& encryptedImage1, const Mat& encryptedImage2) {
    double chiSquared = 0.0;
    vector<int> observed(256, 0);
    vector<int> expected(256, 0);
    for (int i = 0; i < encryptedImage1.rows; ++i) {
        for (int j = 0; j < encryptedImage1.cols; ++j) {
            for (int k = 0; k < encryptedImage1.channels(); ++k) {
                observed[encryptedImage1.at<Vec3b>(i, j)[k]]++;
                expected[encryptedImage2.at<Vec3b>(i, j)[k]]++;
            }
        }
    }
    for (int i = 0; i < 256; ++i) {
        chiSquared += pow(observed[i] - expected[i], 2) / expected[i];
    }
    return chiSquared;
}
double calculateHistogramChiSquared(const Mat& encryptedImage) {
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
double calculateInformationEntropy(const Mat& encryptedImage) {
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
void visualizeHistogram(const Mat& encryptedImage) {
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
double calculateEncryptionQuality(const Mat& plainImage, const Mat& encryptedImage) {
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
    double encryptionQuality = sumDiff / totalBytes;
    return encryptionQuality;
}
void hideConfidentialInformation(Mat& stegoImage, const string& name, int number) {
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