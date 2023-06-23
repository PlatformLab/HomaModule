#include "dist.h"
#include "homa.h"
#include "iostream"

/**
 * This program takes one of the five workload distributions and converts
 * it into a fragment of a textformat protobuf used in distbench. It will first
 * merge buckets and truncate cdf_point sizes according to command line arguments
 * then write the cdf_points to stdout and the interval conversion to stderr
 * 
 * Usage:
 * ./dist_to_proto workload [max message length] [min bucket frac]
 * [max size ratio] [gigabits per second]
 */
int main (int argc, char**argv)
{
  int max_message_length = HOMA_MAX_MESSAGE_LENGTH;
  double min_bucket_frac = 0.0025;
  double max_size_ratio = 1.2;
  double gbps = 20.0;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s workload [max message length] [min bucket frac]"
            " [max size ratio] [gbps]\n", argv[0]);
    exit(1);
  }
  if (argc > 2) {
    max_message_length = atoi(argv[2]);
  }
  if (argc > 3) {
    min_bucket_frac = std::stod(argv[3]);
  }
  if (argc > 4) {
    max_size_ratio = std::stod(argv[4]);
  }
  if (argc > 5) {
    gbps = std::stod(argv[5]);
  }

  dist_point_gen generator(argv[1], max_message_length,
                           min_bucket_frac, max_size_ratio);
  std::vector<int> values = generator.values();
  std::vector<double> fractions = generator.CDF_fractions();

  for (size_t i = 0; i < values.size(); ++i) {
    printf("    cdf_points { value: %d, cdf: %20.19f }\n", values[i], fractions[i]);
  }

  /**
   * Convert average size to bits, then divide by gbps and round up to get
   * nanoseconds, then multiply by 2 because request size and response
   * size are equal
   */
  double interval_ns = (std::ceil( (generator.get_mean() * 8.0) / gbps)) * 2;
  fprintf(stderr,"%.0f", interval_ns);
}