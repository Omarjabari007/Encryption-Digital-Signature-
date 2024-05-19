#include <iostream>
#include<algorithm>
#include<map>
#include <bitset>
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
#define ll long long
#define ma 1e9
#define mi -1e9
using namespace cv;
using namespace std;
using namespace CryptoPP;
// key and iv ..
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
SecByteBlock iv(AES::BLOCKSIZE);
double encryption_quality_TEST(const Mat& plainImage, const Mat& encryptedImage) {
    int totalBytes = 256;
    double sumDiff = 0.0;
    vector<int> observedPlain(256, 0);
    vector<int> observedEncrypted(256, 0);

    if (plainImage.channels() == 3) {
        // Handle color images
        for (int i = 0; i < plainImage.rows; ++i) {
            for (int j = 0; j < plainImage.cols; ++j) {
                for (int k = 0; k < plainImage.channels(); ++k) {
                    observedPlain[plainImage.at<Vec3b>(i, j)[k]]++;
                    observedEncrypted[encryptedImage.at<Vec3b>(i, j)[k]]++;
                }
            }
        }
    }
    else if (plainImage.channels() == 1) {
        for (int i = 0; i < plainImage.rows; ++i) {
            for (int j = 0; j < plainImage.cols; ++j) {
                int plainPixel = plainImage.at<uchar>(i, j);
                int encryptedPixel = encryptedImage.at<uchar>(i, j);
                observedPlain[plainPixel]++;
                observedEncrypted[encryptedPixel]++;
            }
        }
    }

    for (int i = 0; i < 256; ++i) {
        sumDiff += abs(observedPlain[i] - observedEncrypted[i]);
    }
    double encryption_quality_ = sumDiff / totalBytes;
    return encryption_quality_;
}
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
double NPCR_test(const Mat& Encrypted_Image_1, const Mat& Encrypted_Image_2) {
    if (Encrypted_Image_1.size() != Encrypted_Image_2.size() || Encrypted_Image_1.type() != Encrypted_Image_2.type()) {
        cerr << "Error: Image sizes or types do not match." << endl;
        return 0;
    }
    int totalPixels = Encrypted_Image_1.rows * Encrypted_Image_1.cols * Encrypted_Image_1.channels();
    int differentPixels = 0;
    if (Encrypted_Image_1.channels() == 3)
    {
        for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
            for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
                for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                    if (Encrypted_Image_1.at<Vec3b>(i, j)[k] != Encrypted_Image_2.at<Vec3b>(i, j)[k]) {
                        ++differentPixels;
                    }
                }
            }
        }
    }
    else if (Encrypted_Image_1.channels() == 1) {
        for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
            for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
                for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                    if (Encrypted_Image_1.at<uchar>(i, j) != Encrypted_Image_2.at<uchar>(i, j)) {
                        ++differentPixels;
                    }
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
    if (Encrypted_Image_1.channels() == 3) {


        for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
            for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
                for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                    sumDiff += abs(Encrypted_Image_1.at<Vec3b>(i, j)[k] - Encrypted_Image_2.at<Vec3b>(i, j)[k]);
                }
            }
        }
    }
    else if (Encrypted_Image_1.channels() == 1) {
        for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
            for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
                for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                    if (Encrypted_Image_1.at<uchar>(i, j) != Encrypted_Image_2.at<uchar>(i, j)) {
                        sumDiff += abs(Encrypted_Image_1.at<uchar>(i, j) != Encrypted_Image_2.at<uchar>(i, j));

                    }
                }
            }
        }

    }
    double uaci = (sumDiff / (totalPixels * 255.0)) * 100.0;
    return uaci;
}
double HD_TEST(const Mat& Encrypted_Image_1, const Mat& Encrypted_Image_2) {
    int totalBits = Encrypted_Image_1.rows * Encrypted_Image_1.cols * Encrypted_Image_1.channels() * 8;
    int hammingDistance = 0;
    if (Encrypted_Image_1.channels() == 3)
    {
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
    }
    else if (Encrypted_Image_1.channels() == 1) {
        for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
            for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
                for (int k = 0; k < Encrypted_Image_1.channels(); ++k) {
                    for (int l = 0; l < 8; ++l) {
                        if (((Encrypted_Image_1.at<uchar>(i, j) != Encrypted_Image_2.at<uchar>(i, j)) >> l) & 1)
                            ++hammingDistance;
                    }
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
    if (Encrypted_Image_1.channels() == 3) {


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
    }
    else if (Encrypted_Image_1.channels() == 1) {
        for (int i = 0; i < Encrypted_Image_1.rows; ++i) {
            for (int j = 0; j < Encrypted_Image_1.cols; ++j) {
                int pixelValue1 = Encrypted_Image_1.at<uchar>(i, j);
                int pixelValue2 = Encrypted_Image_2.at<uchar>(i, j);
                observed[pixelValue1]++;
                expected[pixelValue2]++;
            }
        }
        for (int i = 0; i < 256; ++i) {
            if (expected[i] > 0) {
                chiSquared += pow(observed[i] - expected[i], 2) / expected[i];
            }
        }
    }

    return chiSquared;
}
double Chi_Squared_Histogram(const Mat& encryptedImage) {
    double chiSquared = 0.0;
    vector<int> observed(256, 0);
    if (encryptedImage.channels() == 3) {
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
    }
    else if (encryptedImage.channels() == 1) {
        for (int i = 0; i < encryptedImage.rows; ++i) {
            for (int j = 0; j < encryptedImage.cols; ++j) {
                int pixelValue = encryptedImage.at<uchar>(i, j);
                observed[pixelValue]++;
            }
        }
        double expectedFrequency = static_cast<double>(encryptedImage.rows * encryptedImage.cols * encryptedImage.channels()) / 256.0;
        for (int i = 0; i < 256; ++i) {
            if (expectedFrequency > 0) {
                chiSquared += pow(observed[i] - expectedFrequency, 2) / expectedFrequency;
            }
        }
    }

    return chiSquared;
}
void Histogram_Visualization(const Mat& encryptedImage) {
    if (encryptedImage.empty()) {
        cerr << "Error: Encrypted image is empty." << endl;
        return;
    }

    vector<Mat> bgr_planes;
    split(encryptedImage, bgr_planes);

    if (bgr_planes.size() != 3) {
        cout << "Error -> Should be 3 channels ." << endl;
        return;
    }
    int histSize = 256;
    float range[] = { 0, 256 };
    const float* histRange = { range };
    bool uniform = true, accumulate = false;
    Mat b_hist, g_hist, r_hist;
    calcHist(&bgr_planes[0], 1, nullptr, Mat(), b_hist, 1, &histSize, &histRange, uniform, accumulate);
    calcHist(&bgr_planes[1], 1, nullptr, Mat(), g_hist, 1, &histSize, &histRange, uniform, accumulate);
    calcHist(&bgr_planes[2], 1, nullptr, Mat(), r_hist, 1, &histSize, &histRange, uniform, accumulate);
    int hist_w = 512, hist_h = 400;
    int bin_w = cvRound((double)hist_w / histSize);
    Mat histImage(hist_h, hist_w, CV_8UC3, Scalar(0, 0, 0));
    normalize(b_hist, b_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
    normalize(g_hist, g_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
    normalize(r_hist, r_hist, 0, histImage.rows, NORM_MINMAX, -1, Mat());
    for (int i = 1; i < histSize; i++) {
        line(histImage, Point(bin_w * (i - 1), hist_h - cvRound(b_hist.at<float>(i - 1))),
            Point(bin_w * i, hist_h - cvRound(b_hist.at<float>(i))),
            Scalar(255, 0, 0), 2, 8, 0);
        line(histImage, Point(bin_w * (i - 1), hist_h - cvRound(g_hist.at<float>(i - 1))),
            Point(bin_w * i, hist_h - cvRound(g_hist.at<float>(i))),
            Scalar(0, 255, 0), 2, 8, 0);
        line(histImage, Point(bin_w * (i - 1), hist_h - cvRound(r_hist.at<float>(i - 1))),
            Point(bin_w * i, hist_h - cvRound(r_hist.at<float>(i))),
            Scalar(0, 0, 255), 2, 8, 0);
    }
    namedWindow("Histogram", WINDOW_AUTOSIZE);
    imshow("Histogram", histImage);
    waitKey(0);
}
double InformationEnrtopy_TEST(const Mat& encryptedImage)
{
    double entropy = 0.0;
    vector<int> histogram(256, 0);
    if (encryptedImage.channels() == 3) {


        for (int i = 0; i < encryptedImage.rows; ++i) {
            for (int j = 0; j < encryptedImage.cols; ++j) {
                for (int k = 0; k < encryptedImage.channels(); ++k) {
                    histogram[encryptedImage.at<Vec3b>(i, j)[k]]++;
                }
            }
        }

        double totalPixels = encryptedImage.rows * encryptedImage.cols * encryptedImage.channels();
        for (int i = 0; i < 256; ++i) {
            if (histogram[i] > 0) {
                double probability = static_cast<double>(histogram[i]) / totalPixels;
                entropy += probability * log2(1 / probability);
            }
        }
    }
    else if (encryptedImage.channels() == 1)
    {
        for (int i = 0; i < encryptedImage.rows; ++i) {
            for (int j = 0; j < encryptedImage.cols; ++j) {
                int pixelValue = encryptedImage.at<uchar>(i, j);
                histogram[pixelValue]++;
            }
        }
        double totalPixels = encryptedImage.rows * encryptedImage.cols * encryptedImage.channels();
        for (int i = 0; i < 256; ++i) {
            if (histogram[i] > 0) {
                double probability = static_cast<double>(histogram[i]) / totalPixels;
                entropy += probability * log2(1 / probability);
            }
        }
    }

    return entropy;
}
Mat vector_into_mat(const vector<unsigned char>& data, const Size& size, int type) {
    if (data.size() != size.width * size.height * CV_MAT_CN(type)) {
        cerr << "Data size does not match the expected image dimensions and type." << endl;
        return Mat();  // Return an empty Mat to indicate an error.
    }
    Mat image(size, type);
    memcpy(image.data, data.data(), data.size());
    return image;
}
vector<unsigned char> encrypt_data0(const vector<unsigned char>& data, size_t& encryptedSize, const SecByteBlock& keyUsed) {
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(keyUsed, keyUsed.size(), iv);

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
void toggleBit(SecByteBlock& block, size_t bitIndex) {
    size_t byteIndex = bitIndex / 8;
    size_t bitInByteIndex = bitIndex % 8;
    block[byteIndex] ^= (1 << bitInByteIndex);
}
void performKeySensitivityTest(const Mat& image) {
    auto start = chrono::high_resolution_clock::now();
    vector<unsigned char> imageData = mat_into_vector(image);
    size_t encryptedSize;
    vector<unsigned char> encryptedData = encrypt_data0(imageData, encryptedSize, key);

    int side = cvRound(sqrt(encryptedData.size()));
    Mat encryptedImageDisplay = Mat(side, side, CV_8UC1, encryptedData.data());
    SecByteBlock keyModified = key;
    toggleBit(keyModified, 0);
    vector<unsigned char> encryptedDataModified = encrypt_data0(imageData, encryptedSize, keyModified);
    Mat encryptedImageModifiedDisplay = Mat(side, side, CV_8UC1, encryptedDataModified.data());
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << "Displaying encrypted images with original and modified keys." << endl;
    waitKey(0);
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
    cout << "Choice10:" << " " << "Quit :" << endl;
    cout << "(Encryption  System .. !)" << endl;
    bool flag = true;
    while (flag) {
        int choice;
        cout << "Enter choice between  --_ 1 and 10 _ --: ";
        cin >> choice;

        if (choice == 1) {
            imshow("Encrypted image 1", encryptedImageDisplay);
            imshow("Encrypted image 2", encryptedImageModifiedDisplay);
            imwrite("Encrypted_image1.bmp", encryptedImageDisplay); //as_BMP
            imwrite("Encrypted_image2.bmp", encryptedImageModifiedDisplay); //as_BMP
            waitKey(0);
        }
        else if (choice == 2) {
            double npc_result = NPCR_test(encryptedImageDisplay, encryptedImageModifiedDisplay);
            cout << "NPCR <Number of Pixel Change Rate>: " << fixed << setprecision(2) << npc_result << "%" << endl;
        }
        else if (choice == 3) {
            double uaci = UACI_TEST(encryptedImageDisplay, encryptedImageModifiedDisplay);
            cout << "<UACI (Unified Average CI>: " << fixed << setprecision(2) << uaci * 100 << "%" << endl;
        }
        else if (choice == 4) {
            double hd = HD_TEST(encryptedImageDisplay, encryptedImageModifiedDisplay);
            cout << "HD <Hamming Distance>: " << fixed << setprecision(2) << hd << "%" << endl;
        }
        else if (choice == 5) {
            double chiSquared = Chi_Square_TEST(encryptedImageDisplay, encryptedImageModifiedDisplay);
            cout << "Chi_Square_Result: " << chiSquared << endl;
        }
        else if (choice == 6) {
            double chi_squared_theoretical = 293.0; // given_value
            double Histogram_chi_squared = Chi_Squared_Histogram(encryptedImageDisplay);
            cout << "Histogram Chi_squared Result: " << Histogram_chi_squared << endl;
            cout << "Theoretical Chi_squared Result: " << chi_squared_theoretical << endl;
            cout << "Histogram Analysis Result: ";
            if (Histogram_chi_squared < chi_squared_theoretical) {
                cout << "Passed." << endl;
            }
            else {
                cout << "Failed." << endl;
            }
            Histogram_Visualization(encryptedImageDisplay); // visualize 
        }
        else if (choice == 7) {
            double information_entropy_ = InformationEnrtopy_TEST(encryptedImageDisplay);
            cout << "Information Entropy: " << information_entropy_ << endl;
        }
        else if (choice == 8) {
            double encryption_quality_ = encryption_quality_TEST(image, encryptedImageDisplay);
            cout << "Encryption Quality: " << fixed << setprecision(2) << encryption_quality_ << endl;
        }
        else if (choice == 9) {
            double encryption_time_measure = duration.count();
            cout << "Encryption Time: " << fixed << setprecision(5) << encryption_time_measure << " seconds" << endl;
            cout << " Encryption Time in NCPB  Can't be done in this  easy  , some addition tests and hardware needs to measure first ." << endl;
        }
        else if (choice ==10) {
            flag = false;
        }
        else {
            cout << "Inavlid ,, please choose a number betwee 1 and 10 . " << endl;
        }
    }
} //key
void performPlaintextSensitivityTest(const Mat& image) {
    Mat image2 = image.clone();
    image2.at<Vec3b>(0, 0)[0] ^= 0x01;
    auto start = chrono::high_resolution_clock::now();
    vector<unsigned char> imageData1 = mat_into_vector(image);
    vector<unsigned char> imageData2 = mat_into_vector(image2);
    size_t encryptedSize1, encryptedSize2;
    vector<unsigned char> encryptedData1 = encrypt_data0(imageData1, encryptedSize1, key);
    vector<unsigned char> encryptedData2 = encrypt_data0(imageData2, encryptedSize2, key);

    Mat encryptedImage1 = Mat(image.size(), image.type(), encryptedData1.data());
    Mat encryptedImage2 = Mat(image.size(), image.type(), encryptedData2.data());

    normalize(encryptedImage1, encryptedImage1, 0, 255, NORM_MINMAX, CV_8UC1);
    normalize(encryptedImage2, encryptedImage2, 0, 255, NORM_MINMAX, CV_8UC1);
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end - start;
    cout << "Displaying encrypted images with original and slightly modified plaintext." << endl;
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
    cout << "Choice10:" << " " << "Quit :" << endl;
    cout << "(Encryption  System .. !)" << endl;
    bool flag = true;
    while (flag) {
        int choice;
        cout << "Enter choice between  --_ 1 and 10 _ --: ";
        cin >> choice;
        if (choice == 1) {
            imshow("Encrypted image 1", encryptedImage1);
            imshow("Encrypted image 2", encryptedImage2);
            imwrite("Encrypted_image1.bmp", encryptedImage1); //as_BMP
            imwrite("Encrypted_image2.bmp", encryptedImage2); //as_BMP
            waitKey(0);
        }
        else if (choice == 2) {
            double npc_result = NPCR_test(encryptedImage1, encryptedImage2);
            cout << "NPCR (Number of Pixel Change Rate): " << fixed << setprecision(2) << npc_result << "%" << endl;
        }
        else if (choice == 3) {
            double uaci = UACI_TEST(encryptedImage1, encryptedImage2);
            cout << "UACI (Unified Average Change Intensity): " << fixed << setprecision(2) << uaci << "%" << endl;

        }
        else if (choice == 4) {
            double hd = HD_TEST(encryptedImage1, encryptedImage2);
            cout << "HD (Hamming Distance): " << fixed << setprecision(2) << hd << "%" << endl;
        }
        else if (choice == 5) {
            double chiSquared = Chi_Square_TEST(encryptedImage1, encryptedImage2);
            cout << "Chi_Square_Result: " << chiSquared << endl;
        }
        else if (choice == 6) {
            double chi_squared_theoretical = 293.0; // given_value
            double Histogram_chi_squared = Chi_Squared_Histogram(encryptedImage1);
            cout << "Histogram Chi_squared Result: " << Histogram_chi_squared << endl;
            cout << "Theoretical Chi_squared Result: " << chi_squared_theoretical << endl;
            cout << "Histogram Analysis Result: ";
            if (Histogram_chi_squared < chi_squared_theoretical) {
                cout << "Passed." << endl;
            }
            else {
                cout << "Failed." << endl;
            }
            Histogram_Visualization(encryptedImage1); // visualize 
        }
        else if (choice == 7) {
            double information_entropy_ = InformationEnrtopy_TEST(encryptedImage1);
            cout << "Information Entropy: " << information_entropy_ << endl;
        }
        else if (choice == 8) {
            double encryption_quality_ = encryption_quality_TEST(image, encryptedImage1);
            cout << "Encryption Quality: " << fixed << setprecision(2) << encryption_quality_ << endl;
        }
        else if (choice == 9) {
            double encryption_time_measure = duration.count();
            cout << "Encryption Time: " << fixed << setprecision(5) << encryption_time_measure << " seconds" << endl;
            cout << " Encryption Time in NCPB  Can't be done in this  easy  , some addition tests and hardware needs to measure first ." << endl;

        }
        else if (choice == 10) {
            flag = false;
        }
        else {
            cout << "Inavlid ,, please choose a number betwee 1 and 10 . " << endl;
        }
    }
    waitKey(0);
}
// byte fucntions  :  ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
vector<byte> IntegerIntoByte(const vector<int>& data) {
    return vector<byte>(data.begin(), data.end());
}
vector<int> MatrixIntoVector(const cv::Mat& img) {
    vector<int> ans;
    for (int i = 0; i < img.rows; i++) {
        for (int j = 0; j < img.cols; j++) {
            const cv::Vec3b& Pixel = img.at<cv::Vec3b>(i, j);
            for (int x = 0; x < 3; x++) {
                ans.push_back(Pixel[x]);
            }
        }
    }
    return ans;
}
cv::Mat VectorIntoMatrix(const vector<int>& data, const long long& rows, const long long& cols) {
    long long idx(0);
    cv::Mat img(cols, rows, CV_8UC3, cv::Scalar(0, 0, 0));
    for (long long i = 0; i < rows; i++) {
        for (long long j = 0; j < cols; j++) {
            cv::Vec3b& pixel = img.at<cv::Vec3b>(i, j);
            for (int x = 0; x < 3; x++) {
                pixel[x] = data[idx++];
            }
        }
    }
    return img;
}
vector<byte> encrypt_data(const vector<byte>& data) {
    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);

    vector<byte> cipherText;
    VectorSource(data, true,
        new StreamTransformationFilter(encryptor,
            new VectorSink(cipherText)
        )
    );

    //encryptedSize = cipherText.size();
    //return vector<unsigned char>(cipherText.begin(), cipherText.end());
    return cipherText;
}
vector<byte> decrypt_data(const vector<byte>& encryptedData) {
    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);
    vector<byte> decryptedData;
    VectorSource(encryptedData, true,
        new StreamTransformationFilter(decryptor,
            new VectorSink(decryptedData)
        )
    );
    return decryptedData;
}
vector<int> ByteIntoInteger(vector<byte>& data) {
    return vector<int>(data.begin(), data.end());
}
//
void hideDataInImage(Mat& image, const string& data) {
    // Convert data to binary
    string binaryData;
    for (char c : data) {
        binaryData += bitset<8>(c).to_string();
    }
    int dataIndex = 0;
    for (int row = 0; row < image.rows; ++row) {
        for (int col = 0; col < image.cols; ++col) {
            if (dataIndex < binaryData.size()) {
                Vec3b pixel = image.at<Vec3b>(row, col);
                for (int color = 0; color < 3; ++color) {
                    if (dataIndex < binaryData.size()) {
                        pixel[color] = (pixel[color] & 0xFE) | (binaryData[dataIndex] - '0');
                        ++dataIndex;
                    }
                }
                image.at<Vec3b>(row, col) = pixel;
            }
            else {
                return;
            }
        }
    }
}
string retrieveDataFromImage(const Mat& image, int dataLength) {
    string binaryData;
    int dataIndex = 0;
    for (int row = 0; row < image.rows; ++row) {
        for (int col = 0; col < image.cols; ++col) {
            if (dataIndex < dataLength * 8) {
                Vec3b pixel = image.at<Vec3b>(row, col);
                for (int color = 0; color < 3; ++color) {
                    if (dataIndex < dataLength * 8) {
                        binaryData += (pixel[color] & 0x01) ? '1' : '0';
                        ++dataIndex;
                    }
                }
            }
            else {
                break;
            }
        }
    }
    string data;
    for (size_t i = 0; i < binaryData.size(); i += 8) {
        bitset<8> byte(binaryData.substr(i, 8));
        data += char(byte.to_ulong());
    }
    return data;
}
int main() {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    cout << "Choose a data method  ? " << endl; 
    cout << "1- Unsigned Charecter Data " << endl;
    cout << "2- Byte Data" << endl; // better for encryption / decryption 
    int data_method; cin >> data_method; 
    if (data_method == 1) {
        int imageTypeChoice;  // Declaration of the imageTypeChoice variable
        cout << "Select image type:" << endl;
        cout << "1. Color image" << endl;
        cout << "2. Grayscale image" << endl;
        cin >> imageTypeChoice;
        Mat image;
        if (imageTypeChoice == 1) {
            image = imread("C:\\Users\\omarj\\OneDrive\\Documents\\project-photos\\LenaRGB.jpg", IMREAD_COLOR);
        }
        else if (imageTypeChoice == 2) {
            image = imread("C:\\Users\\omarj\\OneDrive\\Documents\\project-photos\\gray.png", IMREAD_GRAYSCALE);
            cout << "Image dimensions: " << image.cols << "x" << image.rows << ", Channels: " << image.channels() << endl;
            if (image.channels() == 1) {
                cvtColor(image, image, COLOR_GRAY2BGR);
            }
            if (image.cols == 0 && image.rows == 0) {
                cout << "Error : Image size is not fixed ! " << endl;
            }
        }
        else {
            cout << "Invalid image type ..." << endl;
            return -1;
        }
        if (image.empty()) {
            cout << "Could not find the image" << endl;
            return -1;
        }
        int choice;
        cout << "Enter choice between 1 and 2 for tests: " << endl;
        cout << "1- Key Sensitivity Attack" << endl;
        cout << "2- Plain TextSenestivity Attack" << endl;
        cin >> choice;
        switch (choice) {
        case 1:
            performKeySensitivityTest(image);
            break;
        case 2:
            performPlaintextSensitivityTest(image);
            break;
        default:
            cout << "Invalid choice. Please select 1 or 2." << endl;
        }
    }
    else {
        // new functions for this method of data ... i will use the byte data only for encrpytion and decryption and maybe for some tests ...
        cout << "Select image type:" << endl;
        cout << "1. Color image" << endl;
        cout << "2. Grayscale image" << endl;
        cout << "3. Hiding image" << endl;
            int color_choice; cin >> color_choice;
            if (color_choice == 1) {
                cout << "Encryption : 1 " << endl;
                cout << "Decryption : 2 " << endl;
           while (true) {
                    int lost; cin >> lost;
                    cv::Mat image = imread("C:\\Users\\omarj\\OneDrive\\Documents\\project-photos\\LenaRGB.jpg", IMREAD_COLOR);
                    vector<int> imageVector = MatrixIntoVector(image);
                    vector<byte> byteVectorImage = IntegerIntoByte(imageVector);
                    vector<byte> omarvector = encrypt_data(byteVectorImage);
                    vector<int> IntegerVector = ByteIntoInteger(omarvector);
                    vector<byte> decryptedByteVector = decrypt_data(omarvector);
                    vector<int> decryptedIntegerVector = ByteIntoInteger(decryptedByteVector);
                    cv::Mat img = VectorIntoMatrix(IntegerVector, image.cols, image.rows);
                    cv::Mat newImg = VectorIntoMatrix(decryptedIntegerVector, img.cols, img.rows);
                    if (lost == 1) {
                        cv::imwrite("C:\\Users\\omarj\\source\\repos\\Sword Art Project\\Sword Art Project\\Byte_Enc_Dec\\encrypted_Byte.bmp", img);
                        cout << "Encrypted Saved ..." << endl;
                        imshow("Encrypted Image", img);
                        waitKey(0);
                    }
                    else if (lost == 2) {
                        cv::imwrite("C:\\Users\\omarj\\source\\repos\\Sword Art Project\\Sword Art Project\\Byte_Enc_Dec\\decrypted.bmp", newImg);
                        cout << "Decrypted Saved ..." << endl;
                        imshow("Decrypted Image", newImg);
                        waitKey(0);
                    }
                    else {
                        break;
                    }
                }
            }
            else if (color_choice == 2) {
                cout << "Encryption : 1 " << endl;
                cout << "Decryption : 2 " << endl;
                while (true) {
                    int lost; cin >> lost;
                    cv::Mat image = imread("C:\\Users\\omarj\\OneDrive\\Documents\\project-photos\\gray.png", IMREAD_GRAYSCALE);
                    vector<int> imageVector = MatrixIntoVector(image);
                    vector<byte> byteVectorImage = IntegerIntoByte(imageVector);
                    vector<byte> omarvector = encrypt_data(byteVectorImage);
                    vector<int> IntegerVector = ByteIntoInteger(omarvector);
                    vector<byte> decryptedByteVector = decrypt_data(omarvector);
                    vector<int> decryptedIntegerVector = ByteIntoInteger(decryptedByteVector);
                    cv::Mat img = VectorIntoMatrix(IntegerVector, image.cols, image.rows);
                    cv::Mat newImg = VectorIntoMatrix(decryptedIntegerVector, img.cols, img.rows);
                    if (lost == 1) {
                        cv::imwrite("C:\\Users\\omarj\\source\\repos\\Sword Art Project\\Sword Art Project\\Byte_Enc_Dec\\encrypted_gray_Byte.bmp", img);
                        cout << "Encrypted Saved ..." << endl;
                        imshow("Encrypted Image", img);
                        waitKey(0);
                    }
                    else if (lost == 2) {
                        cv::imwrite("C:\\Users\\omarj\\source\\repos\\Sword Art Project\\Sword Art Project\\Byte_Enc_Dec\\decrypted_gray_byte.bmp", newImg);
                        cout << "Decrypted Saved ..." << endl;
                        imshow("Decrypted Image", newImg);
                        waitKey(0);
                    }
                    else {
                        break;
                    }
                }
            }
            else {
                string name = "omar_jabari";
                int id = 211144;
                string data = name + to_string(id);
                cout << "Hiding image .. loading ......." << endl;
                cv::Mat image = imread("C:\\Users\\omarj\\OneDrive\\Documents\\project-photos\\PeppersRGB.jpg", IMREAD_COLOR);
                if (image.empty()) {
                    cout << "Could not open or find the image" << endl;
                    return -1;
                }
                hideDataInImage(image, data);
                cv::imwrite("C:\\Users\\omarj\\source\\repos\\Sword Art Project\\Sword Art Project\\Byte_Enc_Dec\\hidden_data_image.bmp", image);
                cout << "Data hidden and image saved ..." << endl;

                cout << "Retrieve hidden data  :  1 " << endl;
                int choice; cin >> choice;
                if (choice == 1) {
                    cv::Mat retrievedImage = imread("C:\\Users\\omarj\\source\\repos\\Sword Art Project\\Sword Art Project\\Byte_Enc_Dec\\hidden_data_image.bmp", IMREAD_COLOR);
                    if (retrievedImage.empty()) {
                        cout << "No File " << endl;
                        return -1;
                    }
                    imshow("Hiding image ", image);
                    waitKey(0);
                    string retrievedData = retrieveDataFromImage(retrievedImage, data.size());
                    cout << "Retrieved data: " << retrievedData << endl;
                }
            }
    }
    return 0;
}