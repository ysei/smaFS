#ifndef common_h
#define common_h

#include <tr1/unordered_map>
#include <string>
#include <functional>

#define M  1 /* mknod */
#define T  2 /* truncate */
#define OW 3 /* open in write mode */
#define R  4 /* rename */
#define U  5 /* unlink */

using namespace std;
using namespace tr1;

typedef unordered_map<string, int> hashmap;

#endif
