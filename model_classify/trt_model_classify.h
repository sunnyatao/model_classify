

#ifdef _WIN32
extern "C"
{



}

#else
#ifdef __cplusplus

extern "C"
{

#endif

	int loadGraphWithLicenceAndPbname(char* pbname_c, char* pbBuf, int pbLen, char* licenceData, int licenceLen, float per_process_gpu_memory_fraction);
	void do_classify_with_pbname(char* pbname_c, float * data, int sample_num, int width, int batch_size, int * out_label, float * out_score, int num_class, char* input_layer_c, char* output_layer_c);
	void unloadGraph_with_pbname(char* pbname_c);
	int setupLicense();

	int loadGraphWithLicence(char* pbBuf, int pbLen, char* licenceData, int licenceLen, float per_process_gpu_memory_fraction);
	void do_classify(float * data, int sample_num, int width, int batch_size, int * out_label, float * out_score, int num_class, char* input_layer_c, char* output_layer_c);
	void unloadGraph();

#ifdef __cplusplus
}
#endif 


#endif