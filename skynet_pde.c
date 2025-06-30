#include <petsc.h>
#include <petscdm.h>
#include <petscdmda.h>
#include <petscts.h>

typedef struct {
  DM        da;         // Distributed array for grid
  Vec       env_data;   // Environmental data (e.g., wind field)
  PetscReal dt;         // Time step
  PetscReal Lx, Ly;     // Domain size [0,Lx] x [0,Ly]
} AppCtx;

// RHS function: Simplified continuity equation
PetscErrorCode RHSFunction(TS ts, PetscReal t, Vec U, Vec F, void *ctx) {
  AppCtx        *app = (AppCtx *)ctx;
  DM            da = app->da;
  PetscScalar   ***u, ***f;
  const PetscScalar *env;
  DMDALocalInfo info;
  PetscReal     hx, hy;

  PetscFunctionBegin;
  DMDAGetLocalInfo(da, &info);
  hx = app->Lx / (PetscReal)(info.mx - 1); // Grid spacing x
  hy = app->Ly / (PetscReal)(info.my - 1); // Grid spacing y
  DMDAVecGetArrayDOF(da, U, &u);
  DMDAVecGetArrayDOF(da, F, &f);
  VecGetArrayRead(app->env_data, &env);

  for (PetscInt i = info.xs; i < info.xs + info.xm; i++) {
    for (PetscInt j = info.ys; j < info.ys + info.ym; j++) {
      PetscScalar rho = u[i][j][0];    // Density
      PetscScalar u_x = u[i][j][1];    // Velocity x-component
      // Continuity: d(rho)/dt = -div(rho*u) (finite difference)
      PetscScalar drho_dx = 0.0;
      if (i > info.xs && i < info.xs + info.xm - 1) {
        drho_dx = (rho * u_x - u[i-1][j][0] * u[i-1][j][1]) / hx;
      }
      f[i][j][0] = -drho_dx; // Continuity equation
      // Momentum: du_x/dt = f_env (simplified, no control yet)
      f[i][j][1] = env[i * info.my + j]; // Environmental force
    }
  }

  DMDAVecRestoreArrayDOF(da, U, &u);
  DMDAVecRestoreArrayDOF(da, F, &f);
  VecRestoreArrayRead(app->env_data, &env);
  PetscFunctionReturn(0);
}

int main(int argc, char **argv) {
  PetscErrorCode ierr;
  PetscInitialize(&argc, &argv, NULL, NULL);

  AppCtx ctx;
  ctx.dt = 0.01;
  ctx.Lx = 100.0; // Domain size x
  ctx.Ly = 100.0; // Domain size y

  // Create 2D grid (10x10 for debugging)
  DM da;
  PetscInt mx = 10, my = 10;
  ierr = DMDACreate2d(PETSC_COMM_WORLD, DM_BOUNDARY_NONE, DM_BOUNDARY_NONE, DMDA_STENCIL_STAR,
                      mx, my, PETSC_DECIDE, PETSC_DECIDE, 2, 1, NULL, NULL, &da); CHKERRQ(ierr);
  ctx.da = da;
  ierr = DMSetUp(da); CHKERRQ(ierr);

  // Create vectors
  Vec U, F;
  ierr = DMCreateGlobalVector(da, &U); CHKERRQ(ierr);
  ierr = DMCreateGlobalVector(da, &F); CHKERRQ(ierr);
  ierr = VecCreateMPI(PETSC_COMM_WORLD, mx * my, PETSC_DETERMINE, &ctx.env_data); CHKERRQ(ierr);
  ierr = VecSet(ctx.env_data, 0.1); CHKERRQ(ierr); // Constant wind field

  // Initialize state (Gaussian density blob)
  PetscScalar ***u;
  DMDALocalInfo info;
  ierr = DMDAGetLocalInfo(da, &info); CHKERRQ(ierr);
  PetscReal hx = ctx.Lx / (PetscReal)(info.mx - 1);
  PetscReal hy = ctx.Ly / (PetscReal)(info.my - 1);
  ierr = DMDAVecGetArrayDOF(da, U, &u); CHKERRQ(ierr);
  for (PetscInt i = info.xs; i < info.xs + info.xm; i++) {
    for (PetscInt j = info.ys; j < info.ys + info.ym; j++) {
      PetscReal x = i * hx, y = j * hy;
      u[i][j][0] = PetscExpReal(-((x - 50.0) * (x - 50.0) + (y - 50.0) * (y - 50.0)) / 10.0); // Density
      u[i][j][1] = 0.0; // Initial velocity
    }
  }
  ierr = DMDAVecRestoreArrayDOF(da, U, &u); CHKERRQ(ierr);

  // Create time-stepping solver
  TS ts;
  ierr = TSCreate(PETSC_COMM_WORLD, &ts); CHKERRQ(ierr);
  ierr = TSSetDM(ts, da); CHKERRQ(ierr);
  ierr = TSSetProblemType(ts, TS_NONLINEAR); CHKERRQ(ierr);
  ierr = TSSetRHSFunction(ts, NULL, RHSFunction, &ctx); CHKERRQ(ierr);
  ierr = TSSetType(ts, TSRK); CHKERRQ(ierr); // Simpler Runge-Kutta
  ierr = TSSetTimeStep(ts, ctx.dt); CHKERRQ(ierr);
  ierr = TSSetMaxTime(ts, 0.1); CHKERRQ(ierr); // Short time for testing
  ierr = TSSetSolution(ts, U); CHKERRQ(ierr);
  ierr = TSSetFromOptions(ts); CHKERRQ(ierr);

  // Solve
  ierr = TSSolve(ts, U); CHKERRQ(ierr);

  // Output
  PetscViewer viewer;
  ierr = PetscViewerASCIIOpen(PETSC_COMM_WORLD, "skynet_pde.txt", &viewer); CHKERRQ(ierr);
  ierr = VecView(U, viewer); CHKERRQ(ierr);
  ierr = PetscViewerDestroy(&viewer); CHKERRQ(ierr);

  // Clean up
  ierr = TSDestroy(&ts); CHKERRQ(ierr);
  ierr = VecDestroy(&U); CHKERRQ(ierr);
  ierr = VecDestroy(&F); CHKERRQ(ierr);
  ierr = VecDestroy(&ctx.env_data); CHKERRQ(ierr);
  ierr = DMDestroy(&da); CHKERRQ(ierr);
  ierr = PetscFinalize(); CHKERRQ(ierr);
  return 0;
}
