#include <app.h>

#include <iostream>

int main(int argc, char** argv)
{
    return photon::app::Run(argc, argv, std::cout, std::cerr, photon::app::MakeDefaultDeps());
}
